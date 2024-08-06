// Package agentsbomk8s generates SBOMs for Kubernetes workloads and publishes information about generated SBOMs to NATS
package agentsbomk8s

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent"
	containerdaemonrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/containerdaemon"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service"
)

// Opts contains options.
type Opts struct {
	SBOMSubject            string
	SBOMMessagingRepo      messagingrepository.Messaging[cisinapi.Sbom, *cisinapi.Sbom]
	ContainerDaemonRepo    containerdaemonrepository.ContainerDaemon
	SBOMService            service.SBOMService
	SBOMGenerationInterval time.Duration
}

type agentSBOM struct {
	Opts
}

// NewAgent creates a K8s SBOM agent.
func NewAgent(opts Opts) (agent.Agent, error) {
	return agentSBOM{
		opts,
	}, nil
}

func (a agentSBOM) Start(ctx context.Context) error {
	a.startK8sSBOM(ctx)

	return nil
}

func (a agentSBOM) startK8sSBOM(ctx context.Context) {
	go func() {
		// generate SBOMs in time intervals
		ticker := time.NewTicker(a.SBOMGenerationInterval)
		logger := logrus.WithField("type", "sbom")

		logger.Info("start")

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := a.createContainerSBOMs(ctx)
				if err != nil {
					logger.Error(err)
				}
			}
		}
	}()
}

func (a agentSBOM) createContainerSBOMs(ctx context.Context) error {
	logger := logrus.WithField("type", "sbom")

	// list images container daemon
	images, err := a.ContainerDaemonRepo.ListContainerImages(ctx)
	if err != nil {
		return fmt.Errorf("list images: %w", err)
	}

	// generate SBOMs for all images
	for _, image := range images {
		logger.WithField("image", image).Debug("analyze")

		sbomURL, err := a.SBOMService.GenerateSBOM(ctx, image.Image)
		if err != nil {
			return fmt.Errorf("genrate sbom: %w", err)
		}

		logger.WithField("image", image).WithField("url", sbomURL).Debug("sbom generated")

		// publish information about SBOM generation to NATS
		err = a.SBOMMessagingRepo.Send(a.SBOMSubject, &cisinapi.Sbom{
			Image: &cisinapi.Image{
				Image:  image.Image,
				Digest: image.Digest,
			},
			Url: sbomURL,
		})
		if err != nil {
			logger.Error(err)
		}
	}

	return nil
}
