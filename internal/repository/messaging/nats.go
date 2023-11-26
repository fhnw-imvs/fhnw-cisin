package messagingrepository

import (
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type natsRepo struct {
	conn    *nats.Conn
	subject string
}

func NewNATS(url, subject string) (Messaging, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}

	return natsRepo{
		subject: subject,
	}, nil
}

func (n natsRepo) Send(message proto.Message) error {
	data, err := proto.Marshal(message)
	if err != nil {
		return err
	}

	return n.conn.Publish(n.subject, data)
}

func (n natsRepo) Receive() (proto.Message, error) {

}
