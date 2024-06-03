package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

type otelGrpc struct {
	endpoint    string
	serviceName string
}

func (o otelGrpc) GetProvider() trace.TracerProvider {
	return otel.GetTracerProvider()
}

func (o otelGrpc) Start(ctx context.Context) error {
	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(o.endpoint), otlptracegrpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("setup tracing: %w", err)
	}

	otelResource, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(o.serviceName),
		),
	)
	if err != nil {
		return fmt.Errorf("setup tracing: %w", err)
	}

	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(otelResource))

	otel.SetTracerProvider(tracerProvider)

	return nil
}

func NewTracingOtelGrpc(serviceName, endpoint string) Tracing {
	return otelGrpc{
		endpoint:    endpoint,
		serviceName: serviceName,
	}
}
