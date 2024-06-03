package tracing

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

type Tracing interface {
	Start(ctx context.Context) error
	GetProvider() trace.TracerProvider
}
