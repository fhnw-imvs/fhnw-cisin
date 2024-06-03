package sbom

import (
	"fmt"

	apirepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/api"
	registryrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/registry"
	secscanservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/secscan"
	traceservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/trace"
)

type SBOM struct {
	Jaeger      string `default:"http://localhost:14268"`
	ServiceName string `default:"cisin"`
	TraceID     string `arg:""                           required:""`
}

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
