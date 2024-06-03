package sbomservice

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sirupsen/logrus"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	containerdaemonrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/containerdaemon"
	registryrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/registry"
	sbomrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/sbom"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service"
)

const digestSplitLength = 2

type sbomService struct {
	containerDaemonRepo containerdaemonrepository.ContainerDaemon
	registryRepo        registryrepository.Registry
	sbomRepo            sbomrepository.SBOM
}

func New(containerDaemonRepo containerdaemonrepository.ContainerDaemon, registryRepo registryrepository.Registry, sbomRepo sbomrepository.SBOM) service.SBOMService {
	return sbomService{
		containerDaemonRepo: containerDaemonRepo,
		registryRepo:        registryRepo,
		sbomRepo:            sbomRepo,
	}
}

func (s sbomService) GenerateSBOM(ctx context.Context, image string) (string, error) {
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

	remoteSBOM, err := s.sbomRepo.GetSBOMURL(ctx, image)
	if err == nil {
		return remoteSBOM, nil
	}

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
