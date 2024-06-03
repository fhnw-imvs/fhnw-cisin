package list

import (
	"fmt"

	apirepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/api"
	traceservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/trace"
)

type List struct {
	Jaeger      string `default:"http://localhost:14268"`
	ServiceName string `default:"cisin"`
}

func (l List) Run() error {
	apiRepo := apirepository.NewAPI(l.Jaeger)

	traceService := traceservice.New(apiRepo, l.ServiceName)

	traceIDs, err := traceService.List()
	if err != nil {
		return fmt.Errorf("listing traces: %w", err)
	}

	for _, traceID := range traceIDs {
		fmt.Println(traceID)
	}

	return nil
}
