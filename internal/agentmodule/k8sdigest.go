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

// K8sDigestModuleName is the name of the K8s digest module.
const K8sDigestModuleName = "k8s_digest"

type k8sDigestModule struct {
	k8sRepo k8srepository.K8s
}

// NewK8sDigestModule creates a new agent module to analyze images.
func NewK8sDigestModule(k8sRepo k8srepository.K8s) (AgentModule, error) {
	return k8sDigestModule{
		k8sRepo: k8sRepo,
	}, nil
}

func (k k8sDigestModule) Analyze(_ string, _ int, endpoint *flow.Endpoint) (*cisinapi.Analyse, error) {
	podName := endpoint.GetPodName()
	podNamespace := endpoint.GetNamespace()

	// get pod from Kubernetes API
	pod, err := k.k8sRepo.GetPod(context.Background(), podName, podNamespace)
	if err != nil {
		return nil, fmt.Errorf("get pod %s from namespace %s: %w", podName, podNamespace, err)
	}

	digests := make([]string, 0)

	// extract all digests from pod
	for _, container := range pod.Status.ContainerStatuses {
		ref, err := name.ParseReference(container.ImageID)
		if err != nil {
			return nil, fmt.Errorf("parse reference %s: %w", ref, err)
		}

		digests = append(digests, ref.Identifier())
	}

	return &cisinapi.Analyse{
		Results: digests,
	}, nil
}

func (k k8sDigestModule) Compatibility() []cisinapi.WorkloadType {
	return []cisinapi.WorkloadType{cisinapi.WorkloadType_KUBERNETES}
}

func (k k8sDigestModule) ModuleName() string {
	return K8sDigestModuleName
}
