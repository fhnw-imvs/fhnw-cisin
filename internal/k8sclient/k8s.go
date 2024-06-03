package k8sclient

import (
	"fmt"
	"os"
	"path"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func GetK8sClientSet(inCluster bool, configPath string) (*kubernetes.Clientset, error) {
	var config *rest.Config

	var err error

	if inCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("create k8s in cluster config: %w", err)
		}
	} else {
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
