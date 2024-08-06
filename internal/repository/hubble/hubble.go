// Package hubblerepostiory provides access to Cilium Hubble
package hubblerepostiory

import (
	"context"

	"github.com/cilium/cilium/api/v1/flow"
)

// Hubble is the interface to access Hubble.
type Hubble interface {
	// StartFlowChannel start listening for network flows
	StartFlowChannel(ctx context.Context) (chan *Flow, chan error)
}

// Flow represents a network flow.
type Flow struct {
	Flow     *flow.Flow
	NodeName string
}
