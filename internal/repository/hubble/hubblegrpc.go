package hubblerepostiory

import (
	"context"
	"github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hubbleGRPC struct {
	flowClient observer.Observer_GetFlowsClient
	hubbleConn *grpc.ClientConn
}

func NewGRPC(ctx context.Context, address string, dialOptions []grpc.DialOption) (Hubble, error) {
	hubbleConn, err := grpc.Dial(address, dialOptions...)
	if err != nil {
		return nil, err
	}

	flowClient, err := getFlowClient(ctx, hubbleConn)
	if err != nil {
		return nil, err
	}

	return hubbleGRPC{
		flowClient: flowClient,
	}, nil
}

func getFlowClient(ctx context.Context, clientConn *grpc.ClientConn) (observer.Observer_GetFlowsClient, error) {
	oc := observer.NewObserverClient(clientConn)

	flowClient, err := oc.GetFlows(ctx, &observer.GetFlowsRequest{
		Follow: true,
	})
	if err != nil {
		return nil, err
	}

	return flowClient, nil
}

func (h hubbleGRPC) StartFlowChannel(ctx context.Context) (chan *Flow, chan error) {
	flowChan := make(chan *Flow, 1)
	errChan := make(chan error, 1)

	go func() {
		for {
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

			flowChan <- &Flow{
				Flow:     resp.GetFlow(),
				NodeName: resp.GetNodeName(),
			}
		}
	}()

	go func() {
		<-ctx.Done()
		_ = h.hubbleConn.Close()
	}()

	return flowChan, errChan
}
