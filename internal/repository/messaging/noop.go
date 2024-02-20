package messagingrepository

import (
	"context"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
)

type noop[T cisinapi.Connection, U ProtoMessage[T]] struct {
}

func NewNoop[T cisinapi.Connection, U ProtoMessage[T]]() Messaging[T] {
	return noop[T, U]{}
}

func (n noop[T, U]) Send(subject string, message *T) error {
	return nil
}

func (n noop[T, U]) Receive(ctx context.Context, subject, queue string) (chan *T, error) {
	return make(chan *T), nil
}
