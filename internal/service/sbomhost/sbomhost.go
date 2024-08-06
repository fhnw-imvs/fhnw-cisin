// Package sbomhostservice contains a host based implementation of service.SBOMService
package sbomhostservice

import (
	"context"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sirupsen/logrus"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	registryrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/registry"
	sbomrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/sbom"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service"
)

type sbomhostService struct {
	registryRepo registryrepository.Registry
	sbomRepo     sbomrepository.SBOM
	nodeName     string
}

// New creates a new service.SBOMService.
func New(nodeName string, registryRepo registryrepository.Registry, sbomRepo sbomrepository.SBOM) service.SBOMService {
	return sbomhostService{
		registryRepo: registryRepo,
		sbomRepo:     sbomRepo,
		nodeName:     nodeName,
	}
}

func (s sbomhostService) GenerateSBOM(_ context.Context, location string) (string, error) {
	logrus.Infof("generate host sbom")

	// create SBOM
	sbomImageName := fmt.Sprintf("%s/%s", s.registryRepo.GetURL(), s.nodeName)

	data, err := s.sbomRepo.GetSBOM(location)
	if err != nil {
		return "", fmt.Errorf("get SBOM from filesystem: %w", err)
	}

	sbomImage, err := createSBOM(data)
	if err != nil {
		return "", err
	}

	logrus.WithField("target", sbomImageName).Info("SBOM location")

	// push SBOM
	err = s.registryRepo.Push(sbomImageName, sbomImage)
	if err != nil {
		return "", fmt.Errorf("registry repo: %w", err)
	}

	return sbomImageName, nil
}

func createSBOM(data []byte) (v1.Image, error) {
	sbomImage, err := mutate.AppendLayers(empty.Image, static.NewLayer(data, constant.SBOMMediaType))
	if err != nil {
		return nil, fmt.Errorf("append image layer: %w", err)
	}

	sbomImage = mutate.ConfigMediaType(sbomImage, types.OCIConfigJSON)
	sbomImage = mutate.MediaType(sbomImage, types.OCIManifestSchema1)

	return sbomImage, nil
}
