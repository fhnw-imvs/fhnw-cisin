package sbomrepository

import "context"

type SBOM interface {
	GetSBOMURL(ctx context.Context, ref string) (string, error)
	GetSBOM(location string) ([]byte, error)
}
