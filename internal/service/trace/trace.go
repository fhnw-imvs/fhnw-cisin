// Package traceservice provides an implementation of service.TraceService
package traceservice

import (
	"encoding/json"
	"fmt"

	apirepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/api"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service"
)

type traceService struct {
	apiRepo     apirepository.API
	serviceName string
}

type trace struct {
	Data []traceData `json:"data"`
}

type traceData struct {
	TraceID   string         `json:"traceID"`
	Spans     []traceSpan    `json:"spans"`
	Processes traceProcesses `json:"processes"`
}

type traceSpan struct {
	TraceID       string               `json:"traceID"`
	SpanID        string               `json:"spanID"`
	OperationName string               `json:"operationName"`
	References    []traceSpanReference `json:"references"`
	StartTime     int64                `json:"startTime"`
	Duration      int                  `json:"duration"`
	Tags          []traceTag           `json:"tags"`
	ProcessID     string               `json:"processID"`
}

type traceProcesses struct {
	P1 traceProcess `json:"p1"`
}

type traceProcess struct {
	ServiceName string     `json:"serviceName"`
	Tags        []traceTag `json:"tags"`
}

type traceTag struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type traceSpanReference struct {
	RefType string `json:"refType"`
	TraceID string `json:"traceID"`
	SpanID  string `json:"spanID"`
}

// New creates a new service.TraceService.
func New(apiRepo apirepository.API, serviceName string) service.TraceService {
	return traceService{
		apiRepo:     apiRepo,
		serviceName: serviceName,
	}
}

func (t traceService) List() ([]string, error) {
	// get traces from API
	data, err := t.apiRepo.Get(fmt.Sprintf("/api/traces?service=%s", t.serviceName))
	if err != nil {
		return nil, fmt.Errorf("could not get traces: %w", err)
	}

	receivedTrace := trace{}

	err = json.Unmarshal(data, &receivedTrace)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal traces: %w", err)
	}

	// extract trace ids
	traceIDs := make([]string, 0, len(receivedTrace.Data))
	for _, item := range receivedTrace.Data {
		traceIDs = append(traceIDs, item.TraceID)
	}

	return traceIDs, nil
}

func (t traceService) ListSBOMs(traceID string) ([]string, error) {
	// request trace from API
	data, err := t.apiRepo.Get(fmt.Sprintf("/api/traces/%s", traceID))
	if err != nil {
		return nil, fmt.Errorf("could not get traces: %w", err)
	}

	receivedTrace := trace{}

	err = json.Unmarshal(data, &receivedTrace)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal traces: %w", err)
	}

	// extract SBOM urls from trace
	sbomURLs := make([]string, 0)

	for _, item := range receivedTrace.Data {
		for _, span := range item.Spans {
			for _, tag := range span.Tags {
				if tag.Key != "sboms" {
					continue
				}

				spanSBOMs := make([]string, 0)

				err = json.Unmarshal([]byte(tag.Value), &spanSBOMs)
				if err != nil {
					return nil, fmt.Errorf("could not unmarshal span sboms: %w", err)
				}

				for _, sbom := range spanSBOMs {
					if sbom == "" {
						continue
					}

					sbomURLs = append(sbomURLs, sbom)
				}
			}
		}
	}

	return sbomURLs, nil
}
