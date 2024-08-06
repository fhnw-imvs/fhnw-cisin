// Package agent contains an interface for CISIN agent packages
package agent

import (
	"context"
)

// Agent is the interface for agents.
type Agent interface {
	// Start starts the agent
	Start(ctx context.Context) error
}
