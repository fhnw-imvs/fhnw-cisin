package sbomrepository

import (
	"bytes"
	"context"
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/source/directorysource"
)

type syftFSSBOM struct{}

func (s syftFSSBOM) GetSBOM(path string) ([]byte, error) {
	directorySource, err := directorysource.New(directorysource.Config{
		Path: path,
		Base: path,
	})
	if err != nil {
		return nil, fmt.Errorf("create directory source: %w", err)
	}

	sbom, err := syft.CreateSBOM(context.Background(), directorySource, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("create sbom: %w", err)
	}

	buffer := bytes.NewBuffer(nil)

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("create cyclonedxjson format encoder: %w", err)
	}

	err = encoder.Encode(buffer, *sbom)
	if err != nil {
		return nil, fmt.Errorf("encode sbom: %w", err)
	}

	return buffer.Bytes(), nil
}

func NewSyftFSSBOM() SBOM {
	return syftFSSBOM{}
}

func (s syftFSSBOM) GetSBOMURL(_ context.Context, _ string) (string, error) {
	return "", nil
}
