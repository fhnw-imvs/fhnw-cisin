package hubblerepostiory

import (
	"context"

	"github.com/cilium/cilium/api/v1/flow"
)

type Hubble interface {
	StartFlowChannel(ctx context.Context) (chan *Flow, chan error)
}

type Flow struct {
	Flow     *flow.Flow
	NodeName string
}
