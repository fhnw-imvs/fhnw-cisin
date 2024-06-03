package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/k8sclient"
	k8srepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/k8s"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/tracing"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/server"
)

type Server struct {
	Nats                   nats   `embed:""       prefix:"nats-"`
	Otel                   otel   `embed:""       prefix:"otel-"`
	K8s                    k8s    `embed:""       prefix:"k8s-"`
	WorkerpoolSize         int    `default:"50"`
	WorkerpoolMaxQueueSize int    `default:"1000"`
	LogLevel               string `default:"info"`
}

type nats struct {
	Address           string `default:"localhost:4222"`
	ConnectionSubject string `default:"hubble"`
	SBOMSubject       string `default:"sbom"`
	SBOMVMSubject     string `default:"sbomvm"`
	ConnectionQueue   string `default:"hubble"`
	SBOMQueue         string `default:"sbom"`
	SBOMVMQueue       string `default:"sbomvm"`
}

type otel struct {
	Address     string `default:"localhost:4317"`
	ServiceName string `default:"cisin"`
}
type k8s struct {
	ConfigPath string
	InCluster  bool
}

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

	connectionMessagingRepo, err := messagingrepository.NewNATS[cisinapi.Connection, *cisinapi.Connection](s.Nats.Address)
	if err != nil {
		return fmt.Errorf("create connection messaging repo: %w", err)
	}

	sbomMessagingRepo, err := messagingrepository.NewNATS[cisinapi.Sbom, *cisinapi.Sbom](s.Nats.Address)
	if err != nil {
		return fmt.Errorf("create sbom messaging repo: %w", err)
	}

	sbomVMMessagingRepo, err := messagingrepository.NewNATS[cisinapi.SbomVM, *cisinapi.SbomVM](s.Nats.Address)
	if err != nil {
		return fmt.Errorf("create sbom messaging repo: %w", err)
	}

	tracingRepo := tracing.NewTracingOtelGrpc(s.Otel.ServiceName, s.Otel.Address)

	err = tracingRepo.Start(rootCtx)
	if err != nil {
		return fmt.Errorf("create tracing repo: %w", err)
	}

	k8sClientset, err := k8sclient.GetK8sClientSet(s.K8s.InCluster, s.K8s.ConfigPath)
	if err != nil {
		return fmt.Errorf("get k8s client: %w", err)
	}

	k8sRepo := k8srepository.New(k8sClientset)

	cisinServer := server.NewServer(server.Opts{
		ConnectionMessagingRepo: connectionMessagingRepo,
		SBOMMessagingRepo:       sbomMessagingRepo,
		SBOMVMMessagingRepo:     sbomVMMessagingRepo,
		TracingRepo:             tracingRepo,
		WpSize:                  s.WorkerpoolSize,
		WpMaxQueueSize:          s.WorkerpoolMaxQueueSize,
		ConnectionSubject:       s.Nats.ConnectionSubject,
		SBOMSubject:             s.Nats.SBOMSubject,
		SBOMVMSubject:           s.Nats.SBOMVMSubject,
		ConnectionQueue:         s.Nats.ConnectionQueue,
		SBOMQueue:               s.Nats.SBOMQueue,
		SBOMVMQueue:             s.Nats.SBOMVMQueue,
		K8sRepo:                 k8sRepo,
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
