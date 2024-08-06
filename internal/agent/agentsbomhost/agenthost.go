// Package agentsbomhost generates SBOMs for external workloads and publishes information about generated SBOMs to NATS
package agentsbomhost

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service"
)

// Opts contains options.
type Opts struct {
	SBOMHostSubject        string
	SBOMHostMessagingRepo  messagingrepository.Messaging[cisinapi.Sbom, *cisinapi.Sbom]
	SBOMService            service.SBOMService
	SBOMGenerationInterval time.Duration
	SBOMRoot               string
}

type agentSBOM struct {
	Opts
}

// NewAgent creates a host SBOM agent.
func NewAgent(opts Opts) (agent.Agent, error) {
	return agentSBOM{
		opts,
	}, nil
}

func (a agentSBOM) Start(ctx context.Context) error {
	a.startSBOMHost(ctx)

	return nil
}

func (a agentSBOM) startSBOMHost(ctx context.Context) {
	go func() {
		// generate SBOMs in time intervals
		ticker := time.NewTicker(a.SBOMGenerationInterval)
		logger := logrus.WithField("type", "sbom")

		logger.Info("start")

		err := a.createSBOMHost(ctx)
		if err != nil {
			logger.Error(err)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := a.createSBOMHost(ctx)
				if err != nil {
					logger.Error(err)
				}
			}
		}
	}()
}

func (a agentSBOM) createSBOMHost(ctx context.Context) error {
	logger := logrus.WithField("type", "sbom")

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}

	logger.WithField("host", hostname).Debug("analyze")

	// generate SBOM
	sbomURL, err := a.SBOMService.GenerateSBOM(ctx, a.SBOMRoot)
	if err != nil {
		return fmt.Errorf("genrate sbom: %w", err)
	}

	logger.WithField("host", hostname).WithField("url", sbomURL).Debug("sbom generated")

	// publish information about SBOM generation to NATS
	err = a.SBOMHostMessagingRepo.Send(a.SBOMHostSubject, &cisinapi.Sbom{
		Host: &cisinapi.Host{
			Hostname: hostname,
		},
		Url: sbomURL,
	})
	if err != nil {
		logger.Error(err)
	}

	return nil
}
