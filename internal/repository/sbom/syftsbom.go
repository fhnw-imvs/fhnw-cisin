package sbomrepository

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/image/containerd"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/source/stereoscopesource"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sirupsen/logrus"
)

type syftSBOM struct {
	imgSrc    image.Source
	insecure  bool
	namespace string
}

func NewSyftSBOM(imgSrc image.Source, namespace string, insecure bool) SBOM {
	_ = os.Setenv("CONTAINERD_NAMESPACE", namespace)

	return syftSBOM{
		imgSrc:    imgSrc,
		insecure:  insecure,
		namespace: namespace,
	}
}

func (s syftSBOM) GetSBOM(ref string) ([]byte, error) {
	logrus.WithField("image", ref).Debugf("generate SBOM")

	imageProvider := containerd.NewDaemonProvider(&file.TempDirGenerator{}, image.RegistryOptions{
		InsecureSkipTLSVerify: s.insecure,
	}, s.namespace, ref, &image.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
	})

	img, err := imageProvider.Provide(context.Background())
	if err != nil {
		return nil, fmt.Errorf("could not generate image from source: %w", err)
	}

	imgSrc := stereoscopesource.New(img, stereoscopesource.ImageConfig{})

	sbom, err := syft.CreateSBOM(context.Background(), imgSrc, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("could not generate SBOM: %w", err)
	}

	buffer := bytes.NewBuffer(nil)

	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	if err != nil {
		return nil, fmt.Errorf("create cyclonedxjson format encoder: %w", err)
	}

	err = encoder.Encode(buffer, *sbom)
	if err != nil {
		return nil, fmt.Errorf("encode sbom: %w", err)
	}

	return buffer.Bytes(), nil
}

func (s syftSBOM) GetSBOMURL(ctx context.Context, ref string) (string, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse image ref: %w", err)
	}

	_, err = download.SBOMCmd(ctx, options.RegistryOptions{}, options.SBOMDownloadOptions{}, ref, io.Discard)
	if err != nil {
		return "", fmt.Errorf("download sbom: %w", err)
	}

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
