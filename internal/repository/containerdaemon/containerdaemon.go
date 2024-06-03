package containerdaemonrepository

import (
	"context"
)

type ContainerDaemon interface {
	GetDigest(ctx context.Context, ref string) (string, error)
	ListContainerImages(ctx context.Context) ([]Image, error)
}

type Image struct {
	Image  string
	Digest string
}
