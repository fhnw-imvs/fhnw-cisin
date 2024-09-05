// Copyright (c) 2024 Esra Siegert
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Package agentsbomhost generates SBOMs for external workloads and publishes information about generated SBOMs to NATS
package agentsbomhost

import (
	"context"
	"fmt"
	"os"
	"time"

	cisinapi "github.com/fhnw-imvs/fhnw-cisin/gen/go/proto"
	"github.com/fhnw-imvs/fhnw-cisin/internal/agent"
	messagingrepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/messaging"
	"github.com/fhnw-imvs/fhnw-cisin/internal/service"
	"github.com/sirupsen/logrus"
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
