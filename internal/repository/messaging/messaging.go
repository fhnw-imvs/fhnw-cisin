package messagingrepository

import (
	"context"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
)

type Messaging[T cisinapi.Connection] interface {
	Send(subject string, message *T) error
	Receive(ctx context.Context, subject, queue string) (chan *T, error)
}
