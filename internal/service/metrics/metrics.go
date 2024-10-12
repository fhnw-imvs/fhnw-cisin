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

package metricsservice

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fhnw-imvs/fhnw-cisin/internal/id"
	"io"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/fhnw-imvs/fhnw-cisin/internal/constant"
	registryrepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/registry"
	"github.com/fhnw-imvs/fhnw-cisin/internal/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type metricsService struct {
	traceService   service.TraceService
	secScanService service.SecScanService
	registryRepo   registryrepository.Registry
	address        string
	metrics        *prometheus.GaugeVec
	workloadIDs    map[string]bool
	updateInterval time.Duration
}

type traceResult struct {
	vulnerabilities []traceVulnerabilityResult
	workloadIDs     []string
}

type traceVulnerabilityResult struct {
	severity string
	id       string
}

func NewMetricsService(address string, updateInterval time.Duration, traceService service.TraceService, secScanService service.SecScanService, registryRepo registryrepository.Registry) service.MetricsService {
	return &metricsService{
		traceService:   traceService,
		secScanService: secScanService,
		registryRepo:   registryRepo,
		address:        address,
		metrics: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cisin_workload_cve",
			Help: "Describes a CVE present in the cluster",
		}, []string{
			"namespace",
			"kind",
			"name",
			"workload_id",
			"severity",
			"cve",
		}),
		updateInterval: updateInterval,
	}
}

func (m *metricsService) Start(ctx context.Context) error {
	var server http.Server

	go func() {
		server = http.Server{
			Addr:    m.address,
			Handler: promhttp.Handler(),
			//nolint:mnd,gomnd
			ReadHeaderTimeout: 5 * time.Second,
		}

		_ = server.ListenAndServe()
	}()

	go func() {
		<-ctx.Done()

		//nolint:mnd,gomnd
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		defer cancel()

		//nolint:contextcheck
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		ticker := time.NewTicker(m.updateInterval)

		for {
			select {
			case <-ctx.Done():
			case <-ticker.C:
				err := m.updateMetrics()
				if err != nil {
					logrus.Errorf("update metrics: %v", err)
				}
			}
		}
	}()

	return nil
}

func (m *metricsService) updateMetrics() error {
	trace, err := m.traceService.List()
	if err != nil {
		return fmt.Errorf("list trace: %w", err)
	}

	sbomURLToTraceResult, err := m.getTraceResult(trace)
	if err != nil {
		return fmt.Errorf("get trace result: %w", err)
	}

	currentWorkloadIDs := make(map[string]bool)

	for _, tr := range sbomURLToTraceResult {
		for _, workloadID := range tr.workloadIDs {
			currentWorkloadIDs[workloadID] = true

			for _, v := range tr.vulnerabilities {
				namesapce, kind, name, err := id.ParseID(workloadID)
				if err != nil {
					continue
				}

				m.metrics.WithLabelValues(namesapce, kind, name, workloadID, v.severity, v.id).Set(1)
			}
		}
	}

	m.updateWorkloadIDs(currentWorkloadIDs)

	return nil
}

func (m *metricsService) getTraceResult(trace *service.Trace) (map[string]*traceResult, error) {
	sbomURLToTraceResult := make(map[string]*traceResult)

	for _, t := range trace.Data {
		for _, span := range t.Spans {
			for _, tag := range span.Tags {
				if tag.Key != constant.SBOMsTraceTag {
					continue
				}

				sbomURLs := make([]string, 0)

				err := json.Unmarshal([]byte(tag.Value), &sbomURLs)
				if err != nil {
					return nil, fmt.Errorf("unmarshal sbom tag: %w", err)
				}

				err = m.setTraceResults(span.OperationName, sbomURLToTraceResult, sbomURLs)
				if err != nil {
					return nil, fmt.Errorf("set trace results: %w", err)
				}
			}
		}
	}

	return sbomURLToTraceResult, nil
}

func (m *metricsService) setTraceResults(workloadID string, traceResults map[string]*traceResult, sbomURLs []string) error {
	for _, sbomURL := range sbomURLs {
		if traceResults[sbomURL] == nil {
			traceResults[sbomURL] = &traceResult{}
		} else {
			if !slices.Contains(traceResults[sbomURL].workloadIDs, workloadID) {
				traceResults[sbomURL].workloadIDs = append(traceResults[sbomURL].workloadIDs, workloadID)
			}

			continue
		}

		sbomPaths, err := m.getSBOMs(sbomURL)
		if err != nil {
			return fmt.Errorf("get SBOMs: %w", err)
		}

		for _, sbomPath := range sbomPaths {
			result, err := m.secScanService.Scan(sbomPath)
			if err != nil {
				return fmt.Errorf("sec scan %w", err)
			}

			defer os.Remove(sbomPath)

			for _, match := range result.Matches {
				traceResults[sbomURL].vulnerabilities = append(traceResults[sbomURL].vulnerabilities, traceVulnerabilityResult{
					severity: match.Vulnerability.Severity,
					id:       match.Vulnerability.ID,
				})
			}
		}
	}

	return nil
}

func (m *metricsService) updateWorkloadIDs(currentWorkloadIDs map[string]bool) {
	for workloadID := range m.workloadIDs {
		if _, ok := currentWorkloadIDs[workloadID]; ok {
			continue
		}

		m.metrics.DeletePartialMatch(prometheus.Labels{
			"workload_id": workloadID,
		})
	}

	m.workloadIDs = currentWorkloadIDs
}

func (m *metricsService) getSBOMs(sbomURL string) ([]string, error) {
	image, err := m.registryRepo.Pull(sbomURL)
	if err != nil {
		return nil, fmt.Errorf("pull sbom: %w", err)
	}

	layers, err := image.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get layers: %w", err)
	}

	sboms := make([]string, 0)

	for _, layer := range layers {
		mediaType, err := layer.MediaType()
		if err != nil {
			return nil, fmt.Errorf("failed to get media type: %w", err)
		}

		if mediaType != constant.SBOMMediaType {
			continue
		}

		reader, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("failed to uncompress layer: %w", err)
		}

		f, err := os.CreateTemp("", "cisin-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary file: %w", err)
		}

		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read from reader: %w", err)
		}

		_, err = f.Write(data)
		if err != nil {
			return nil, fmt.Errorf("failed to write to temporary file: %w", err)
		}

		sboms = append(sboms, f.Name())
	}

	return sboms, nil
}
