// Package sbomrepository provides SBOMs
package sbomrepository

import "context"

// SBOM is an interface to access/generate SBOMs.
type SBOM interface {
	// GetSBOMURL returns the URL to a SBOM
	GetSBOMURL(ctx context.Context, ref string) (string, error)
	// GetSBOM returns a SBOM
	GetSBOM(location string) ([]byte, error)
}
