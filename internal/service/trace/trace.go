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

// Package traceservice provides an implementation of service.TraceService
package traceservice

import (
	"encoding/json"
	"fmt"
	"time"

	apirepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/api"
	"github.com/fhnw-imvs/fhnw-cisin/internal/service"
)

type traceService struct {
	apiRepo      apirepository.API
	serviceName  string
	historyLimit time.Duration
}

// New creates a new service.TraceService.
func New(apiRepo apirepository.API, serviceName string, historyLimit time.Duration) service.TraceService {
	return traceService{
		apiRepo:      apiRepo,
		serviceName:  serviceName,
		historyLimit: historyLimit,
	}
}

func (t traceService) ListIDs() ([]string, error) {
	receivedTrace, err := t.List()
	if err != nil {
		return nil, err
	}

	// extract trace ids
	traceIDs := make([]string, 0, len(receivedTrace.Data))
	for _, item := range receivedTrace.Data {
		traceIDs = append(traceIDs, item.TraceID)
	}

	return traceIDs, nil
}

func (t traceService) List() (*service.Trace, error) {
	// get traces from API
	data, err := t.apiRepo.Get(fmt.Sprintf("/api/traces?service=%s&start_time_max=%s", t.serviceName, time.Now().Add(-t.historyLimit).Format(time.RFC3339Nano)))
	if err != nil {
		return nil, fmt.Errorf("could not get traces: %w", err)
	}

	receivedTrace := service.Trace{}

	err = json.Unmarshal(data, &receivedTrace)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal traces: %w", err)
	}

	return &receivedTrace, nil
}

func (t traceService) ListSBOMs(traceID string) ([]string, error) {
	// request trace from API
	data, err := t.apiRepo.Get(fmt.Sprintf("/api/traces/%s", traceID))
	if err != nil {
		return nil, fmt.Errorf("could not get traces: %w", err)
	}

	receivedTrace := service.Trace{}

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
