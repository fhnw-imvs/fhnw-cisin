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

package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
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

// NewTracingOtelGrpc returns a otel based implementation of Tracing.
func NewTracingOtelGrpc(serviceName, endpoint string) Tracing {
	return otelGrpc{
		endpoint:    endpoint,
		serviceName: serviceName,
	}
}
