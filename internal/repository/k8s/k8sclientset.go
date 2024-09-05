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

package k8srepository

import (
	"context"
	"fmt"
	"os"
	"path"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/fhnw-imvs/fhnw-cisin/internal/constant"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type k8s struct {
	clientSet *kubernetes.Clientset
}

// NewK8sClientSet returns a client set based implementation of K8s.
func NewK8sClientSet(inCluster bool, configPath string) (K8s, error) {
	clientSet, err := getK8sClientSet(inCluster, configPath)
	if err != nil {
		return nil, err
	}

	return k8s{
		clientSet: clientSet,
	}, nil
}

func (k k8s) GetPod(ctx context.Context, name, namespace string) (*corev1.Pod, error) {
	pod, err := k.clientSet.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s from namespace %s: %w", name, namespace, err)
	}

	return pod, nil
}

func (k k8s) GetReplicaSet(ctx context.Context, name, namespace string) (*appsv1.ReplicaSet, error) {
	replicaSet, err := k.clientSet.AppsV1().ReplicaSets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get replicaset %s from namespace %s: %w", name, namespace, err)
	}

	return replicaSet, nil
}

func (k k8s) GetExternalWorkload(ctx context.Context, name, namespace string) (*v2.CiliumExternalWorkload, error) {
	obj, err := k.clientSet.RESTClient().Get().Namespace(name).Resource(v2.CEWKindDefinition).Name(name).Do(ctx).Get()
	if err != nil {
		return nil, fmt.Errorf("get external workload %s from namespace %s: %w", name, namespace, err)
	}

	w, ok := obj.(*v2.CiliumExternalWorkload)
	if !ok {
		return nil, fmt.Errorf("could not cast object to CiliumExternalWorkload: %w", constant.ErrInvalid)
	}

	return w, nil
}

func getK8sClientSet(inCluster bool, configPath string) (*kubernetes.Clientset, error) {
	var config *rest.Config

	var err error

	if inCluster {
		// if running on Kubernetes read config from mounted service account
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("create k8s in cluster config: %w", err)
		}
	} else {
		// read config from provided path
		config, err = getConfigFromPath(configPath)
		if err != nil {
			return nil, err
		}
	}

	k8sClientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create k8s clientset: %w", err)
	}

	return k8sClientSet, nil
}

func getConfigFromPath(configPath string) (*rest.Config, error) {
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get user home dir: %w", err)
		}

		configPath = path.Join(home, ".kube", "config")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read k8s config file: %w", err)
	}

	clientConfig, err := clientcmd.NewClientConfigFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("create k8s client config: %w", err)
	}

	config, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("create k8s rest config: %w", err)
	}

	return config, nil
}
