package agentsbomvm

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

type Opts struct {
	SBOMVMSubject          string
	SBOMVMMessagingRepo    messagingrepository.Messaging[cisinapi.SbomVM, *cisinapi.SbomVM]
	SBOMService            service.SBOMService
	SBOMGenerationInterval time.Duration
	SBOMRoot               string
}

type agentSBOM struct {
	Opts
}

func NewAgent(opts Opts) (agent.Agent, error) {
	return agentSBOM{
		opts,
	}, nil
}

func (a agentSBOM) Start(ctx context.Context) error {
	a.startVMSBOM(ctx)

	return nil
}

func (a agentSBOM) startVMSBOM(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(a.SBOMGenerationInterval)
		logger := logrus.WithField("type", "sbom")

		logger.Info("start")

		err := a.createVMSBOM(ctx)
		if err != nil {
			logger.Error(err)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := a.createVMSBOM(ctx)
				if err != nil {
					logger.Error(err)
				}
			}
		}
	}()
}

func (a agentSBOM) createVMSBOM(ctx context.Context) error {
	logger := logrus.WithField("type", "sbom")

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}

	logger.WithField("host", hostname).Debug("analyze")

	sbomURL, err := a.SBOMService.GenerateSBOM(ctx, a.SBOMRoot)
	if err != nil {
		return fmt.Errorf("genrate sbom: %w", err)
	}

	logger.WithField("host", hostname).WithField("url", sbomURL).Debug("sbom generated")

	err = a.SBOMVMMessagingRepo.Send(a.SBOMVMSubject, &cisinapi.SbomVM{
		Hostname: hostname,
		Url:      sbomURL,
	})
	if err != nil {
		logger.Error(err)
	}

	return nil
}
