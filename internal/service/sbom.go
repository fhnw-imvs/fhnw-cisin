package service

import "context"

// SBOMService provides SBOM related services.
type SBOMService interface {
	// GenerateSBOM generate a SBOM
	GenerateSBOM(ctx context.Context, identifier string) (string, error)
}
