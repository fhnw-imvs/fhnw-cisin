package server

import (
	"context"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/safemap"
	"slices"
	"sync"
	"time"
)

type Server interface {
	Start(ctx context.Context) error
}

type server struct {
	messagingRepo messagingrepository.Messaging[cisinapi.Connection]
	neighbourhood safemap.SafeMap[string, []neighbour]
	participants  safemap.SafeMap[string, endpoint]
	wpSize        int
	subject       string
	queue         string
}

func NewServer(subject, queue string, wpSize int, messagingRepo messagingrepository.Messaging[cisinapi.Connection]) Server {
	return server{
		messagingRepo: messagingRepo,
		neighbourhood: safemap.NewSafeMap[string, []neighbour](),
		participants:  safemap.NewSafeMap[string, endpoint](),
		wpSize:        wpSize,
		subject:       subject,
		queue:         queue,
	}
}

type endpoint struct {
	id        string
	results   map[string]*cisinapi.Analyse
	timestamp time.Time
}

type neighbour struct {
	id        string
	timestamp time.Time
}

func (s server) Start(ctx context.Context) error {
	wg := sync.WaitGroup{}

	for range s.wpSize {
		connectionChan, err := s.messagingRepo.Receive(ctx, s.subject, s.queue)
		if err != nil {
			return err
		}

		wg.Add(1)

		go func() {
			defer wg.Done()

			for connection := range connectionChan {
				src := connection.GetSource()
				dest := connection.GetDestination()
				now := time.Now()

				s.participants.Set(src.GetId(), endpoint{
					id:        src.GetId(),
					results:   src.GetResults(),
					timestamp: now,
				})

				s.participants.Set(dest.GetId(), endpoint{
					id:        dest.GetId(),
					results:   src.GetResults(),
					timestamp: now,
				})

				neighbourhood, _ := s.neighbourhood.Get(src.GetId())

				i := slices.IndexFunc(neighbourhood, func(n neighbour) bool {
					return n.id == dest.GetId()
				})

				if i == -1 {
					neighbourhood = append(neighbourhood, neighbour{
						id:        dest.GetId(),
						timestamp: now,
					})
				} else {
					neighbourhood[i] = neighbour{
						id:        dest.GetId(),
						timestamp: now,
					}
				}

				s.neighbourhood.Set(src.GetId(), neighbourhood)

				logrus.Info("message received")
			}
		}()
	}

	wg.Wait()

	return nil
}
