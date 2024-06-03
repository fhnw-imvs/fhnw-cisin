package registryrepository

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Registry interface {
	ImageExist(ref string) (bool, error)
	Push(ref string, image v1.Image) error
	Pull(ref string) (v1.Image, error)
	GetURL() string
}
