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

//nolint:dupl // independent module
package agentmodule

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/api/v1/flow"
	cisinapi "github.com/fhnw-imvs/fhnw-cisin/gen/go/proto"
	k8srepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/k8s"
	"github.com/google/go-containerregistry/pkg/name"
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
