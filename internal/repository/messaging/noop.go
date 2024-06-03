package messagingrepository

import (
	"context"
)

type noop[T any, U protoMessage[T]] struct{}

func NewNoop[T any, U protoMessage[T]]() Messaging[T, U] {
	return noop[T, U]{}
}

func (n noop[T, U]) Send(_ string, _ U) error {
	return nil
}

func (n noop[T, U]) Receive(_ context.Context, _, _ string) (chan U, error) {
	return make(chan U), nil
}
