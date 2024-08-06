// Package server contains the command to start the CISIN server.
package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	k8srepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/k8s"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/tracing"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/server"
)

// Server is the command to start the CISIN server.
type Server struct {
	Nats                   nats     `embed:""                                                                                         envprefix:"CISIN_NATS_"                prefix:"nats-"`
	Otel                   otel     `embed:""                                                                                         envprefix:"CISIN_OTEL_"                prefix:"otel-"`
	K8s                    k8s      `embed:""                                                                                         envprefix:"CISIN_K8S_"                 prefix:"k8s-"`
	WorkerpoolSize         int      `default:"50"                                                                                     env:"CISIN_WORKER_POOL_SIZE"           help:"Number of workers to process NATS messages"`
	WorkerpoolMaxQueueSize int      `default:"1000"                                                                                   env:"CISIN_WORKER_POOL_MAX_QUEUE_SIZE" help:"Max. number of messages in queue to process"`
	LogLevel               string   `default:"info"                                                                                   env:"CISIN_LOG_LEVEL"                  help:"Log level to use"`
	ExcludeWorkloads       []string `default:"cisin/DaemonSet/cisin-agent,cisin/StatefulSet/cisin-nats,cisin/Deployment/cisin-server" env:"CISIN_EXCLUDE_WORKLOADS"          help:"Workload to exclude from processing"`
}

type nats struct {
	Address           string `default:"localhost:4222" env:"ADDRESS"            help:"NATS address"`
	ConnectionSubject string `default:"hubble"         env:"CONNECTION_SUBJECT" help:"Subject to receive flows"`
	SBOMSubject       string `default:"sbom"           env:"SBOM_SUBJECT"       help:"Subject to receive SBOM messages"`
	ConnectionQueue   string `default:"hubble"         env:"CONNECTION_QUEUE"   help:"Queue name to receive flows"`
	SBOMQueue         string `default:"sbom"           env:"SBOM_QUEUE"         help:"Queue name to receive SBOM messages"`
}

type otel struct {
	Address     string `default:"localhost:4317" env:"ADDRESS"      help:"Address to publish traces"`
	ServiceName string `default:"cisin"          env:"SERVICE_NAME" help:"Service name to use"`
}
type k8s struct {
	ConfigPath string `default:"/etc/kubernetes/admin.conf" env:"CONFIG_PATH" help:"Path to Kubernetes config"`
	InCluster  bool   `default:"true"                       env:"IN_CLUSTER"  help:"Use default Kubernetes config from pod"`
}

// Run executes the command
//
//nolint:funlen
func (s Server) Run() error {
	sigChan := make(chan os.Signal, 1)
	errChan := make(chan error)
	rootCtx, cancel := context.WithCancel(context.Background())

	defer cancel()

	signal.Notify(sigChan, os.Interrupt)

	level, err := logrus.ParseLevel(s.LogLevel)
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	logrus.SetLevel(level)

	// setup NATS connection
	connectionMessagingRepo, err := messagingrepository.NewNATS[cisinapi.Connection, *cisinapi.Connection](s.Nats.Address)
	if err != nil {
		return fmt.Errorf("create connection messaging repo: %w", err)
	}

	sbomMessagingRepo, err := messagingrepository.NewNATS[cisinapi.Sbom, *cisinapi.Sbom](s.Nats.Address)
	if err != nil {
		return fmt.Errorf("create sbom messaging repo: %w", err)
	}

	// setup tracing
	tracingRepo := tracing.NewTracingOtelGrpc(s.Otel.ServiceName, s.Otel.Address)

	err = tracingRepo.Start(rootCtx)
	if err != nil {
		return fmt.Errorf("create tracing repo: %w", err)
	}

	// setup Kubernetes client
	k8sRepo, err := k8srepository.NewK8sClientSet(s.K8s.InCluster, s.K8s.ConfigPath)
	if err != nil {
		return fmt.Errorf("create k8s repository: %w", err)
	}

	cisinServer := server.NewServer(server.Opts{
		ConnectionMessagingRepo: connectionMessagingRepo,
		SBOMMessagingRepo:       sbomMessagingRepo,
		TracingRepo:             tracingRepo,
		WpSize:                  s.WorkerpoolSize,
		WpMaxQueueSize:          s.WorkerpoolMaxQueueSize,
		ConnectionSubject:       s.Nats.ConnectionSubject,
		SBOMSubject:             s.Nats.SBOMSubject,
		ConnectionQueue:         s.Nats.ConnectionQueue,
		SBOMQueue:               s.Nats.SBOMQueue,
		K8sRepo:                 k8sRepo,
		ExcludeWorkloads:        s.ExcludeWorkloads,
	})

	go func() {
		err = cisinServer.Start(rootCtx)
		errChan <- err
	}()

	select {
	case <-sigChan:
	case err = <-errChan:
		if err != nil {
			return err
		}
	}

	return nil
}
