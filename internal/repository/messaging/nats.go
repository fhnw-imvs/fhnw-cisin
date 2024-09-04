// Copyright (c) 2024 Esra Siegert
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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

// NewNATS returns a NATS based implementation of Messaging.
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
