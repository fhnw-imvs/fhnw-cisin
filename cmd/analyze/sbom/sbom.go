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
