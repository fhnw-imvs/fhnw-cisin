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

// Package secscanservice contains a Grype based implementation of service.SecScanService
package secscanservice

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/fhnw-imvs/fhnw-cisin/internal/constant"
	registryrepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/registry"
	"github.com/fhnw-imvs/fhnw-cisin/internal/service"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type secScanService struct {
	registryRepo registryrepository.Registry
}

// New creates a new service.SecScanService.
func New(registryRepo registryrepository.Registry) service.SecScanService {
	return secScanService{
		registryRepo: registryRepo,
	}
}

func (s secScanService) Scan(sbomURLs []string) error {
	// update vulnerability datatbase
	_, err := exec.Command("grype", "db", "update").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to grype db: %w", err)
	}

	// scan every SBOM from provided URLs
	for _, sbomURL := range sbomURLs {
		image, err := s.registryRepo.Pull(sbomURL)
		if err != nil {
			return fmt.Errorf("failed to pull image: %w", err)
		}

		layers, err := image.Layers()
		if err != nil {
			return fmt.Errorf("failed to get layers: %w", err)
		}

		for _, layer := range layers {
			err = printVulnerabilities(layer)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func printVulnerabilities(layer v1.Layer) error {
	mediaType, err := layer.MediaType()
	if err != nil {
		return fmt.Errorf("failed to get media type: %w", err)
	}

	if mediaType != constant.SBOMMediaType {
		return nil
	}

	reader, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("failed to uncompress layer: %w", err)
	}

	f, err := os.CreateTemp("", "cisin-")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	defer os.Remove(f.Name())

	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read from reader: %w", err)
	}

	_, err = f.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	//#nosec:G204
	outpput, err := exec.Command("grype", fmt.Sprintf("sbom:%s", f.Name())).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to compress sbom: %w", err)
	}

	fmt.Printf("%s\n", string(outpput))

	return nil
}
