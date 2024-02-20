package messagingrepository

import (
	"context"
	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"google.golang.org/protobuf/proto"
)

type ProtoMessage[T cisinapi.Connection] interface {
	*T
	proto.Message
}

type ProtoMessageImpl[T cisinapi.Connection] struct {
	proto.Message
}
type natsRepo[T cisinapi.Connection, U ProtoMessage[T]] struct {
	conn *nats.Conn
}

func NewNATS[T cisinapi.Connection, U ProtoMessage[T]](address string) (Messaging[T], error) {
	nc, err := nats.Connect(address)
	if err != nil {
		return nil, err
	}

	return natsRepo[T, U]{
		conn: nc,
	}, nil
}

func (n natsRepo[T, U]) Send(subject string, message *T) error {
	logrus.Trace("send message")

	data, err := proto.Marshal(U(message))
	if err != nil {
		return err
	}

	return n.conn.Publish(subject, data)
}

func (n natsRepo[T, U]) Receive(ctx context.Context, subject, queue string) (chan *T, error) {
	chanMsg := make(chan *nats.Msg)
	chanT := make(chan *T)

	_, err := n.conn.ChanQueueSubscribe(subject, queue, chanMsg)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case msg := <-chanMsg:
				var t T

				if msg.Data == nil {
					continue
				}

				err := proto.Unmarshal(msg.Data, U(&t))
				if err != nil {
					continue
				}

				chanT <- &t
			case <-ctx.Done():
				close(chanMsg)
			}
		}
	}()

	return chanT, nil
}
