package k8srepository

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type K8s interface {
	GetPod(ctx context.Context, name, namespace string) (*corev1.Pod, error)
	GetReplicaSet(ctx context.Context, name, namespace string) (*appsv1.ReplicaSet, error)
}

type k8s struct {
	clientset *kubernetes.Clientset
}

func New(clientset *kubernetes.Clientset) K8s {
	return k8s{
		clientset: clientset,
	}
}

func (k k8s) GetPod(ctx context.Context, name, namespace string) (*corev1.Pod, error) {
	pod, err := k.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s from namespace %s: %w", name, namespace, err)
	}

	return pod, nil
}

func (k k8s) GetReplicaSet(ctx context.Context, name, namespace string) (*appsv1.ReplicaSet, error) {
	replicaSet, err := k.clientset.AppsV1().ReplicaSets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get replicaset %s from namespace %s: %w", name, namespace, err)
	}

	return replicaSet, nil
}
