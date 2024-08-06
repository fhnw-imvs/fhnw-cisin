// Package k8srepository provides access to Kubernetes
package k8srepository

import (
	"context"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// K8s is the interface to access Kubernetes.
type K8s interface {
	// GetPod returns a pod
	GetPod(ctx context.Context, name, namespace string) (*corev1.Pod, error)
	// GetReplicaSet returns a replicaset
	GetReplicaSet(ctx context.Context, name, namespace string) (*appsv1.ReplicaSet, error)
	// GetExternalWorkload returns a Cilium external workload
	GetExternalWorkload(ctx context.Context, name, namespace string) (*v2.CiliumExternalWorkload, error)
}
