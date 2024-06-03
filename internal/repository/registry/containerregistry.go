package registryrepository

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sirupsen/logrus"
)

type containerRegistry struct {
	craneOpts []crane.Option
	url       string
}

func NewContainerRegistry(url, username, secret string, insecure bool) Registry {
	opts := []crane.Option{
		crane.WithAuth(&authn.Basic{
			Username: username,
			Password: secret,
		}),
	}

	if insecure {
		opts = append(opts, crane.Insecure)
	}

	return containerRegistry{
		url:       url,
		craneOpts: opts,
	}
}

func (c containerRegistry) Push(ref string, image v1.Image) error {
	err := crane.Push(image, ref, c.craneOpts...)
	if err != nil {
		return fmt.Errorf("push image to registry: %w", err)
	}

	logrus.WithField("image", ref).Info("image pushed")

	return nil
}

func (c containerRegistry) Pull(ref string) (v1.Image, error) {
	image, err := crane.Pull(ref, c.craneOpts...)
	if err != nil {
		return nil, fmt.Errorf("pull image from registry: %w", err)
	}

	logrus.WithField("image", ref).Info("image pulled")

	return image, nil
}

func (c containerRegistry) ImageExist(ref string) (bool, error) {
	_, err := crane.Head(ref, c.craneOpts...)
	if err != nil {
		var transportErr *transport.Error

		ok := errors.As(err, &transportErr)
		if !ok {
			return false, fmt.Errorf("request registry: %w", err)
		}

		if transportErr.StatusCode == http.StatusNotFound {
			return false, nil
		}
	}

	return true, nil
}

func (c containerRegistry) GetURL() string {
	return c.url
}
