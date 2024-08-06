package sbomrepository

import (
	"bytes"
	"fmt"

	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/sbom"
)

func getSpdxJSONBytes(s *sbom.SBOM) ([]byte, error) {
	buffer := bytes.NewBuffer(nil)

	encoder, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("create spdxjson format encoder: %w", err)
	}

	err = encoder.Encode(buffer, *s)
	if err != nil {
		return nil, fmt.Errorf("encode sbom: %w", err)
	}

	return buffer.Bytes(), nil
}
