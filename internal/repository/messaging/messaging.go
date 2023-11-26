package messagingrepository

import "google.golang.org/protobuf/proto"

type Messaging interface {
	Send(message proto.Message) error
	Receive() (proto.Message, error)
}
