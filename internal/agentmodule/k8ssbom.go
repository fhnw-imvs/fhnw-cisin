package agentmodule

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/cmd/cosign/cli/download"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/oci/remote"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const K8sSBOMModuleName = "k8s_sbom"

type k8sSBOMModule struct {
	clientset *kubernetes.Clientset
}

// NewK8sSBOMModule creates a new agent module to analyze SBOMs
func NewK8sSBOMModule(k8sClientSet *kubernetes.Clientset) (AgentModule, error) {
	return k8sSBOMModule{
		clientset: k8sClientSet,
	}, nil
}

func (k k8sSBOMModule) Analyze(_ string, _ int, endpoint *flow.Endpoint) (*cisinapi.Analyse, error) {
	podName := endpoint.GetPodName()
	podNamespace := endpoint.GetNamespace()

	pod, err := k.clientset.CoreV1().Pods(podNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	sbomURLs := make([]string, 0)

	for _, container := range pod.Spec.Containers {
		ref, err := name.ParseReference(container.Image)
		if err != nil {
			return nil, err
		}

		_, err = download.SBOMCmd(context.Background(), options.RegistryOptions{}, options.SBOMDownloadOptions{}, pod.Spec.Containers[0].Image, io.Discard)
		if err != nil {
			logrus.Infof("need to generate SBOM")

			data, err := getImageSBOM(ref.Name())
			if err != nil {
				return nil, err
			}

			i, err := mutate.AppendLayers(empty.Image, static.NewLayer(data, "text/spdx+json"))
			if err != nil {
				return nil, err
			}

			i = mutate.ConfigMediaType(i, types.OCIConfigJSON)
			i = mutate.MediaType(i, types.OCIManifestSchema1)

			m, err := i.Manifest()
			if err != nil {
				return nil, err
			}

			out, err := json.Marshal(m)
			if err != nil {
				return nil, err
			}

			fmt.Println(string(out))
		} else {
			digest, err := remote.ResolveDigest(ref)
			if err != nil {
				return nil, err
			}

			s, err := remote.SBOMTag(digest)
			if err != nil {
				return nil, err
			}

			sbomURLs = append(sbomURLs, s.String())
		}
	}

	return &cisinapi.Analyse{
		Results: sbomURLs,
	}, nil
}

func (k k8sSBOMModule) Compatibility() []cisinapi.WorkloadType {
	return []cisinapi.WorkloadType{cisinapi.WorkloadType_KUBERNETES}
}

func (k k8sSBOMModule) ModuleName() string {
	return K8sSBOMModuleName
}

func getImageSBOM(ref string) ([]byte, error) {
	logrus.WithField("image", ref).Debugf("generate SBOM")

	imgSrc, err := source.NewFromStereoscopeImage(source.StereoscopeImageConfig{
		Reference: ref,
		From:      image.OciRegistrySource,
	})
	if err != nil {
		return nil, err
	}

	col, rels, lin, err := syft.CatalogPackages(imgSrc, cataloger.Config{
		Search: cataloger.SearchConfig{
			Scope: source.AllLayersScope,
		},
	})
	if err != nil {
		return nil, err
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          col,
			LinuxDistribution: lin,
		},
		Relationships: rels,
		Source:        imgSrc.Describe(),
	}

	buffer := bytes.NewBuffer(nil)

	err = spdxjson.Format2_3().Encode(buffer, s)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
