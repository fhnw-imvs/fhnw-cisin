//nolint:dupl // independent module
package agentmodule

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/google/go-containerregistry/pkg/name"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	k8srepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/k8s"
)

const K8sImageModuleName = "k8s_image"

type k8sImageModule struct {
	k8sRepo k8srepository.K8s
}

// NewK8sImageModule creates a new agent module to analyze images.
func NewK8sImageModule(k8sRepo k8srepository.K8s) (AgentModule, error) {
	return k8sImageModule{
		k8sRepo: k8sRepo,
	}, nil
}

func (k k8sImageModule) Analyze(_ string, _ int, endpoint *flow.Endpoint) (*cisinapi.Analyse, error) {
	podName := endpoint.GetPodName()
	podNamespace := endpoint.GetNamespace()

	pod, err := k.k8sRepo.GetPod(context.Background(), podName, podNamespace)
	if err != nil {
		return nil, fmt.Errorf("get pod %s from namespace %s: %w", pod, podNamespace, err)
	}

	images := make([]string, 0)

	for _, container := range pod.Spec.Containers {
		ref, err := name.ParseReference(container.Image)
		if err != nil {
			return nil, fmt.Errorf("parse reference %s: %w", ref, err)
		}

		images = append(images, ref.Name())
	}

	return &cisinapi.Analyse{
		Results: images,
	}, nil
}

func (k k8sImageModule) Compatibility() []cisinapi.WorkloadType {
	return []cisinapi.WorkloadType{cisinapi.WorkloadType_KUBERNETES}
}

func (k k8sImageModule) ModuleName() string {
	return K8sImageModuleName
}
