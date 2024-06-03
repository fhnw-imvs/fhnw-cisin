package messagingrepository

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type natsRepo[T any, U protoMessage[T]] struct {
	conn *nats.Conn
}

func NewNATS[T any, U protoMessage[T]](address string) (Messaging[T, U], error) {
	natsConnection, err := nats.Connect(address)
	if err != nil {
		return nil, fmt.Errorf("create nats connection: %w", err)
	}

	return natsRepo[T, U]{
		conn: natsConnection,
	}, nil
}

func (n natsRepo[T, U]) Send(subject string, message U) error {
	logrus.Trace("send message")

	data, err := proto.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal data: %w", err)
	}

	if logrus.IsLevelEnabled(logrus.TraceLevel) {
		dataJSON, err := json.Marshal(message)
		if err != nil {
			return fmt.Errorf("marshal data: %w", err)
		}

		logrus.WithFields(logrus.Fields{
			"subject": subject,
			"data":    string(dataJSON),
		}).Debug("send message")
	}

	err = n.conn.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("publish data: %w", err)
	}

	return nil
}

func (n natsRepo[T, U]) Receive(ctx context.Context, subject, queue string) (chan U, error) {
	chanMsg := make(chan *nats.Msg)
	chanU := make(chan U)

	_, err := n.conn.ChanQueueSubscribe(subject, queue, chanMsg)
	if err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}

	go func() {
		for {
			select {
			case msg := <-chanMsg:
				//nolint:varnamelen
				var u U

				u = new(T)

				if msg.Data == nil {
					continue
				}

				err := proto.Unmarshal(msg.Data, u)
				if err != nil {
					continue
				}

				chanU <- u
			case <-ctx.Done():
				close(chanMsg)

				return
			}
		}
	}()

	return chanU, nil
}
