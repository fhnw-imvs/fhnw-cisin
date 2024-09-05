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

// Package sbomimageservice contains image based implementation of service.SBOM
package sbomimageservice

import (
	"context"
	"fmt"
	"strings"

	"github.com/fhnw-imvs/fhnw-cisin/internal/constant"
	containerdaemonrepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/containerdaemon"
	registryrepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/registry"
	sbomrepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/sbom"
	"github.com/fhnw-imvs/fhnw-cisin/internal/service"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sirupsen/logrus"
)

const digestSplitLength = 2

type sbomService struct {
	containerDaemonRepo containerdaemonrepository.ContainerDaemon
	registryRepo        registryrepository.Registry
	sbomRepo            sbomrepository.SBOM
}

// New creates a new service.SBOMService.
func New(containerDaemonRepo containerdaemonrepository.ContainerDaemon, registryRepo registryrepository.Registry, sbomRepo sbomrepository.SBOM) service.SBOMService {
	return sbomService{
		containerDaemonRepo: containerDaemonRepo,
		registryRepo:        registryRepo,
		sbomRepo:            sbomRepo,
	}
}

func (s sbomService) GenerateSBOM(ctx context.Context, image string) (string, error) {
	// check if SBOM already exists
	digest, err := s.containerDaemonRepo.GetDigest(ctx, image)
	if err != nil {
		return "", fmt.Errorf("get digest: %w", err)
	}

	sbomImageName, err := s.getLocalImageName(image, digest)
	if err != nil {
		return "", err
	}

	imageExist, err := s.registryRepo.ImageExist(sbomImageName)
	if err != nil {
		return "", fmt.Errorf("image exist: %w", err)
	}

	if imageExist {
		return sbomImageName, nil
	}

	// check if from image provider exists
	remoteSBOM, err := s.sbomRepo.GetSBOMURL(ctx, image)
	if err == nil {
		return remoteSBOM, nil
	}

	// generate SBOM
	logrus.Infof("need to generate SBOM")

	data, err := s.sbomRepo.GetSBOM(image)
	if err != nil {
		return "", fmt.Errorf("get sbom: %w", err)
	}

	sbomImage, err := createSBOM(data)
	if err != nil {
		return "", err
	}

	logrus.WithField("target", sbomImageName).Info("SBOM location")

	// push SBOM to registry
	err = s.registryRepo.Push(sbomImageName, sbomImage)
	if err != nil {
		return "", fmt.Errorf("registry repo: %w", err)
	}

	return sbomImageName, nil
}

func (s sbomService) getLocalImageName(ref, digest string) (string, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse ref %s: %w", ref, err)
	}

	imagePart := parsedRef.Context().Name()

	imagePart = strings.ReplaceAll(imagePart, ":", "-")

	digestSplit := strings.Split(digest, ":")

	if len(digestSplit) != digestSplitLength {
		return "", constant.ErrInvalid
	}

	return fmt.Sprintf("%s/%s:%s", s.registryRepo.GetURL(), imagePart, digestSplit[1]), nil
}

func createSBOM(data []byte) (v1.Image, error) {
	sbomImage, err := mutate.AppendLayers(empty.Image, static.NewLayer(data, constant.SBOMMediaType))
	if err != nil {
		return nil, fmt.Errorf("append image layer: %w", err)
	}

	sbomImage = mutate.ConfigMediaType(sbomImage, types.OCIConfigJSON)
	sbomImage = mutate.MediaType(sbomImage, types.OCIManifestSchema1)

	return sbomImage, nil
}
