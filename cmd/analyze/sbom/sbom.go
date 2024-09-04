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

// Package sbom contains the command to scan a trace for vulnerabilities based on embedded SBOM urls.
package sbom

import (
	"fmt"

	apirepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/api"
	registryrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/registry"
	secscanservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/secscan"
	traceservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/trace"
)

// SBOM is the command to analyze SBOMs in a trace for vulnerabilities.
type SBOM struct {
	Jaeger      string `default:"http://jaeger:14268" help:"Jaeger address"`
	ServiceName string `default:"cisin"               help:"Service name"`
	TraceID     string `arg:""                        help:"Trace ID to analyze" required:""`
}

// Run executes the command.
func (l SBOM) Run() error {
	apiRepo := apirepository.NewAPI(l.Jaeger)

	traceService := traceservice.New(apiRepo, l.ServiceName)

	sbomURLS, err := traceService.ListSBOMs(l.TraceID)
	if err != nil {
		return fmt.Errorf("list sboms: %w", err)
	}

	registryRepo := registryrepository.NewContainerRegistry("", "", "", true)

	secScanService := secscanservice.New(registryRepo)

	err = secScanService.Scan(sbomURLS)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	return nil
}
