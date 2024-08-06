package sbomrepository

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source/stereoscopesource"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sirupsen/logrus"
)

type syftImageSBOM struct {
	imgSrc         image.Source
	getImgProvider func(namespace, ref string, insecure bool) image.Provider
	insecure       bool
	namespace      string
}

func NewSyftImageSBOM(imgSrc image.Source, getImgProvider func(namespace, ref string, insecure bool) image.Provider, namespace string, insecure bool) SBOM {
	_ = os.Setenv("CONTAINERD_NAMESPACE", namespace)

	return syftImageSBOM{
		imgSrc:         imgSrc,
		getImgProvider: getImgProvider,
		insecure:       insecure,
		namespace:      namespace,
	}
}

func (s syftImageSBOM) GetSBOM(ref string) ([]byte, error) {
	logrus.WithField("image", ref).Debugf("generate SBOM")

	// get image from image provider
	img, err := s.getImgProvider(s.namespace, ref, s.insecure).Provide(context.Background())
	if err != nil {
		return nil, fmt.Errorf("could not generate image from source: %w", err)
	}

	imgSrc := stereoscopesource.New(img, stereoscopesource.ImageConfig{})

	// create SBOM image based
	sbom, err := syft.CreateSBOM(context.Background(), imgSrc, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("could not generate SBOM: %w", err)
	}

	return getSpdxJSONBytes(sbom)
}

func (s syftImageSBOM) GetSBOMURL(ctx context.Context, ref string) (string, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse image ref: %w", err)
	}

	// try to download SBOM
	_, err = download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, ref, io.Discard)
	if err != nil {
		return "", fmt.Errorf("download sbom: %w", err)
	}

	// resolve URL from SBOM
	digest, err := remote.ResolveDigest(parsedRef)
	if err != nil {
		return "", fmt.Errorf("resolve sbom digest: %w", err)
	}

	loadedSBOM, err := remote.SBOMTag(digest)
	if err != nil {
		return "", fmt.Errorf("get sbom tag: %w", err)
	}

	return loadedSBOM.String(), nil
}
