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

// Package id provides helper functions to create and parse ids
package id

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/fhnw-imvs/fhnw-cisin/internal/constant"
	"github.com/sirupsen/logrus"
)

const numberOfIDElements = 3

const (
	// ExternalWorkloadKind is the fake kind for external Cilium workload.
	ExternalWorkloadKind = "Workload"
	// ExternalWorkloadNamespace is the fake namespace for external Cilium workload.
	ExternalWorkloadNamespace = "external"
)

// GetK8sID retrieve the id for a Kubernetes workload.
func GetK8sID(endpoint *flow.Endpoint) (string, error) {
	workloads := endpoint.GetWorkloads()
	if len(workloads) > 0 {
		return getKubernetesWorkloadID(endpoint.GetNamespace(), workloads[0].GetKind(), workloads[0].GetName()), nil
	}

	logrus.WithField("endpoint", endpoint).Debug("no workload")

	if len(endpoint.GetPodName()) > 0 {
		return getKubernetesWorkloadID(endpoint.GetNamespace(), "Pod", endpoint.GetPodName()), nil
	}

	return "", fmt.Errorf("could not evaluate k8s id: %w", constant.ErrNotFound)
}

// ParseID splits an id into it sub parts.
func ParseID(id string) (namespace, kind, name string, err error) {
	split := strings.Split(id, "/")
	if len(split) != numberOfIDElements {
		return "", "", "", fmt.Errorf("id %s is invalid: %w", id, constant.ErrInvalid)
	}

	return split[0], split[1], split[2], nil
}

func getKubernetesWorkloadID(namespace, kind, name string) string {
	return fmt.Sprintf("%s/%s/%s", namespace, kind, name)
}

// GetExternalWorkloadID retrieve the id for an external workload.
func GetExternalWorkloadID(nodeName string) string {
	return fmt.Sprintf("%s/%s/%s", ExternalWorkloadNamespace, ExternalWorkloadKind, nodeName)
}
