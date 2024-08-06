// Package tracing provides tracing possibilities
package tracing

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// Tracing is the interface to access tracing.
type Tracing interface {
	// Start initializes tracing provider
	Start(ctx context.Context) error
	// GetProvider returns tracing provider
	GetProvider() trace.TracerProvider
}
