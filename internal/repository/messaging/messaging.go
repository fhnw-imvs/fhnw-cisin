package messagingrepository

import (
	"context"

	"google.golang.org/protobuf/proto"
)

type protoMessage[T any] interface {
	proto.Message
	*T
}
type Messaging[T any, U protoMessage[T]] interface {
	Send(subject string, message U) error
	Receive(ctx context.Context, subject, queue string) (chan U, error)
}
