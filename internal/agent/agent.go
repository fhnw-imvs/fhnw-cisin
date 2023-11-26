package agent

import (
	"context"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	hubblerepostiory "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/hubble"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"os"
)

type Agent interface {
	Start(ctx context.Context) error
}

type agent struct {
	hubbleRepo    hubblerepostiory.Hubble
	messagingRepo messagingrepository.Messaging
}

func New(hubbleRepo hubblerepostiory.Hubble, messagingRepo messagingrepository.Messaging) Agent {
	return agent{
		hubbleRepo:    hubbleRepo,
		messagingRepo: messagingRepo,
	}
}

func (a agent) Start(ctx context.Context) error {
	flowChan, errChan := a.hubbleRepo.StartFlowChannel(ctx)

	nodeName, err := os.Hostname()
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
			case flow := <-flowChan:
				if flow.NodeName != nodeName {
					continue
				}

				err = a.messagingRepo.Send(&cisinapi.Connection{})
				if err != nil {
					logrus.Error(err)
				}
			case err := <-errChan:
				logrus.Error(err)
			}
		}
	}()

	return nil
}
