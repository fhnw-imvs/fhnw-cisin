package containerdaemonrepository

import (
	"context"
)

// ContainerDaemon is the interface to access a container daemon.
type ContainerDaemon interface {
	// GetDigest returns the digest for an image
	GetDigest(ctx context.Context, ref string) (string, error)
	// ListContainerImages lists image available from container daemon
	ListContainerImages(ctx context.Context) ([]Image, error)
}

// Image represents a container image.
type Image struct {
	Image  string
	Digest string
}
