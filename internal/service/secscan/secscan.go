package secscanservice

import (
	"fmt"
	"io"
	"os"
	"os/exec"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	registryrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/registry"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service"
)

type secScanService struct {
	registryRepo registryrepository.Registry
}

func New(registryRepo registryrepository.Registry) service.SecScanService {
	return secScanService{
		registryRepo: registryRepo,
	}
}

func (s secScanService) Scan(sbomURLs []string) error {
	_, err := exec.Command("grype", "db", "update").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to grype db: %w", err)
	}

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
