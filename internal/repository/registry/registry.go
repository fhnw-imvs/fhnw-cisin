// Package registryrepository provides access to an OCI image registry
package registryrepository

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Registry is the interface to access an OCI image registry.
type Registry interface {
	// ImageExist check if an image is available
	ImageExist(ref string) (bool, error)
	// Push pushes an image to the registry
	Push(ref string, image v1.Image) error
	// Pull pulls an image
	Pull(ref string) (v1.Image, error)
	// GetURL evaluates the URL of image
	GetURL() string
}
