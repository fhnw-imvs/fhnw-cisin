// Copyright (c) 2024 Esra Siegert
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// Package containerdaemonrepository provides access to container daemons
package containerdaemonrepository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"
)

type containerdImage struct {
	client *containerd.Client
}

// NewContainerd is a Containerd base implementation of ContainerDaemon.
func NewContainerd(address, namespace string) (ContainerDaemon, error) {
	client, err := containerd.New(address, containerd.WithDefaultNamespace(namespace))
	if err != nil {
		return nil, fmt.Errorf("create containerd client: %w", err)
	}

	return containerdImage{
		client: client,
	}, nil
}

func (c containerdImage) ListContainerImages(ctx context.Context) ([]Image, error) {
	// list containers from containerd
	containers, err := c.client.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}

	images := make([]Image, 0)

	// evaluate image for each container
	for _, container := range containers {
		task, err := container.Task(ctx, nil)
		if err != nil {
			if errors.Is(err, errdefs.ErrNotFound) {
				continue
			}

			return nil, fmt.Errorf("list container tasks: %w", err)
		}

		status, err := task.Status(ctx)
		if err != nil {
			panic(err)
		}

		if status.Status != containerd.Running {
			continue
		}

		image, err := container.Image(ctx)
		if err != nil {
			return nil, fmt.Errorf("get image: %w", err)
		}

		images = append(images, Image{
			Image:  image.Name(),
			Digest: image.Target().Digest.String(),
		})
	}

	return images, nil
}

func (c containerdImage) GetDigest(ctx context.Context, ref string) (string, error) {
	// parse image reference
	parsedRef, err := name.ParseReference(ref, name.WithDefaultRegistry("docker.io"))
	if err != nil {
		return "", fmt.Errorf("parse reference %s, %w", ref, err)
	}

	logrus.WithField("image", parsedRef.Name()).Debug("get digest")

	// get image from containerd
	img, err := c.client.GetImage(ctx, parsedRef.Name())
	if err != nil {
		if parsedRef.Context().Registry.Name() == "index.docker.io" {
			// Package name adds randomly "index." if registry is "docker.io"
			img, err = c.client.GetImage(ctx, strings.TrimPrefix(parsedRef.Name(), "index."))
			if err != nil {
				return "", fmt.Errorf("could not load digest: %w", err)
			}
		} else {
			return "", fmt.Errorf("could not load digest: %w", err)
		}
	}

	return img.Target().Digest.String(), nil
}
