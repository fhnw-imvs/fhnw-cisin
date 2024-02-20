package server

import (
	"context"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/server"
	"os"
	"os/signal"
)

type Server struct {
	Nats           nats `embed:"" prefix:"nats-"`
	WorkerpoolSize int  `default:"50"`
}

type nats struct {
	Address string `default:"localhost:4222"`
	Subject string `default:"hubble"`
	Queue   string `default:"hubble"`
}

func (s Server) Run() error {
	sigChan := make(chan os.Signal, 1)
	errChan := make(chan error)
	rootCtx, cancel := context.WithCancel(context.Background())

	defer cancel()

	signal.Notify(sigChan, os.Interrupt)

	messagingRepo, err := messagingrepository.NewNATS[cisinapi.Connection](s.Nats.Address)
	if err != nil {
		return err
	}

	se := server.NewServer(s.Nats.Subject, s.Nats.Queue, s.WorkerpoolSize, messagingRepo)

	go func() {
		err = se.Start(rootCtx)
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
