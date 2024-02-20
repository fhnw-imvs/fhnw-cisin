package agentmodule

import (
	"context"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/google/go-containerregistry/pkg/name"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const K8sImageModuleName = "k8s_image"

type k8sImageModule struct {
	clientset *kubernetes.Clientset
}

// NewK8sImageModule creates a new agent module to analyze images
func NewK8sImageModule(k8sClientSet *kubernetes.Clientset) (AgentModule, error) {
	return k8sImageModule{
		clientset: k8sClientSet,
	}, nil
}

func (k k8sImageModule) Analyze(_ string, _ int, endpoint *flow.Endpoint) (*cisinapi.Analyse, error) {
	podName := endpoint.GetPodName()
	podNamespace := endpoint.GetNamespace()

	pod, err := k.clientset.CoreV1().Pods(podNamespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	images := make([]string, 0)

	for _, container := range pod.Spec.Containers {
		ref, err := name.ParseReference(container.Image)
		if err != nil {
			return nil, err
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
