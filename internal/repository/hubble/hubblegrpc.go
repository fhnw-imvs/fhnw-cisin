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

package hubblerepostiory

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hubbleGRPC struct {
	flowClient observer.Observer_GetFlowsClient
	hubbleConn *grpc.ClientConn
}

// NewGRPC represents a GRPC based implementation of Hubble.
func NewGRPC(ctx context.Context, address string, dialOptions []grpc.DialOption) (Hubble, error) {
	hubbleConn, err := grpc.NewClient(address, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("create hubble connection: %w", err)
	}

	flowClient, err := getFlowClient(ctx, hubbleConn)
	if err != nil {
		return nil, err
	}

	return hubbleGRPC{
		hubbleConn: hubbleConn,
		flowClient: flowClient,
	}, nil
}

func getFlowClient(ctx context.Context, clientConn *grpc.ClientConn) (observer.Observer_GetFlowsClient, error) {
	oc := observer.NewObserverClient(clientConn)

	flowClient, err := oc.GetFlows(ctx, &observer.GetFlowsRequest{
		Follow: true,
	})
	if err != nil {
		return nil, fmt.Errorf("get flows: %w", err)
	}

	return flowClient, nil
}

func (h hubbleGRPC) StartFlowChannel(ctx context.Context) (chan *Flow, chan error) {
	flowChan := make(chan *Flow, 1)
	errChan := make(chan error, 1)

	go func() {
		// listen for flows
		for {
			// receive flow
			resp, err := h.flowClient.Recv()
			if err != nil {
				s, ok := status.FromError(err)
				if ok {
					if s.Code() == codes.Canceled {
						return
					}
				}

				errChan <- err
			}

			// send flow to channel
			flowChan <- &Flow{
				Flow:     resp.GetFlow(),
				NodeName: resp.GetNodeName(),
			}
		}
	}()

	go func() {
		// stop receiving flows if context is closed
		<-ctx.Done()

		_ = h.hubbleConn.Close()
	}()

	return flowChan, errChan
}
