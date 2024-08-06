package sbomrepository

import (
	"context"
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source/directorysource"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
)

type syftFSSBOM struct{}

func (s syftFSSBOM) GetSBOM(path string) ([]byte, error) {
	// create syft directory source
	directorySource, err := directorysource.New(directorysource.Config{
		Path: path,
		Base: path,
	})
	if err != nil {
		return nil, fmt.Errorf("create directory source: %w", err)
	}

	// generate SBOM
	sbom, err := syft.CreateSBOM(context.Background(), directorySource, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("create sbom: %w", err)
	}

	return getSpdxJSONBytes(sbom)
}

// NewSyftFSSBOM is a filesystem based implementation of SBOM.
func NewSyftFSSBOM() SBOM {
	return syftFSSBOM{}
}

func (s syftFSSBOM) GetSBOMURL(_ context.Context, _ string) (string, error) {
	return "", constant.ErrNotFound
}
