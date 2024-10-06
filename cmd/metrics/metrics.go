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

package metrics

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	apirepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/api"
	registryrepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/registry"
	metricsservice "github.com/fhnw-imvs/fhnw-cisin/internal/service/metrics"
	secscanservice "github.com/fhnw-imvs/fhnw-cisin/internal/service/secscan"
	traceservice "github.com/fhnw-imvs/fhnw-cisin/internal/service/trace"
)

type Metrics struct {
	Jaeger         string        `default:"http://localhost:14268" help:"Jaeger address"`
	ServiceName    string        `default:"cisin"                  help:"Service name"`
	Address        string        `default:":2112"                  help:"Metrics address"`
	UpdateInterval time.Duration `default:"1h"                     help:"Update interval"`
}

// Run executes the command.
func (l Metrics) Run() error {
	apiRepo := apirepository.NewAPI(l.Jaeger)

	traceService := traceservice.New(apiRepo, l.ServiceName, 0)

	registryRepo := registryrepository.NewContainerRegistry("", "", "", true)

	secScanService := secscanservice.New(registryRepo)

	metricsService := metricsservice.NewMetricsService(l.Address, l.UpdateInterval, traceService, secScanService, registryRepo)

	signals := make(chan os.Signal, 1)

	signal.Notify(signals, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := metricsService.Start(ctx)
	if err != nil {
		return fmt.Errorf("start metrics service: %w", err)
	}

	<-signals

	return nil
}
