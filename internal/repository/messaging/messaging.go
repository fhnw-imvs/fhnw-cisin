// Package messagingrepository provides messaging possibilities
package messagingrepository

import (
	"context"

	"google.golang.org/protobuf/proto"
)

type protoMessage[T any] interface {
	proto.Message
	*T
}

// Messaging is the interface to send and receive Proto messages.
type Messaging[T any, U protoMessage[T]] interface {
	// Send a message
	Send(subject string, message U) error
	// Receive messages
	Receive(ctx context.Context, subject, queue string) (chan U, error)
}
