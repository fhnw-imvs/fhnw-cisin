package agentcmd

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agentmodule"
	ciliumrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/cilium"
	hubblerepostiory "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/hubble"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifacesrepository"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	procrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/proc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"os/signal"
	"path"
)

type Agent struct {
	NodeName    string   `env:"NODE_NAME"`
	ClusterName string   `required:""`
	NodeType    string   `enum:"k8s,vm" default:"k8s"`
	Hubble      hubble   `embed:"" prefix:"hubble-"`
	Nats        nats     `embed:"" prefix:"nats-"`
	K8s         k8s      `embed:"" prefix:"k8s-"`
	Cilium      cilium   `embed:"" prefix:"cilium-"`
	LogLevel    string   `default:"info"`
	Modules     []string `default:"k8s_image,k8s_sbom,vm_proc"`
}

type hubble struct {
	Address string `default:"unix:///var/run/cilium/hubble.sock"`
}

type cilium struct {
	Address string `default:"unix:///var/run/cilium/cilium.sock"`
}

type nats struct {
	Address string `default:"localhost:4222"`
	Noop    bool   `default:"false"`
	Subject string `default:"hubble"`
}

type k8s struct {
	ConfigPath   string
	InCluster    bool
	GenerateSbom bool `name:"generate-sbom"`
}

func (a Agent) Run() error {
	sigChan := make(chan os.Signal, 1)
	rootCtx, cancel := context.WithCancel(context.Background())

	defer cancel()

	signal.Notify(sigChan, os.Interrupt)

	level, err := logrus.ParseLevel(a.LogLevel)
	if err != nil {
		return err
	}

	logrus.SetLevel(level)

	logrus.WithFields(logrus.Fields{
		"nodeName":      a.NodeName,
		"clusterName":   a.ClusterName,
		"nodeType":      a.NodeType,
		"hubbleAddress": a.Hubble.Address,
		"ciliumAddress": a.Cilium.Address,
		"k8sInCluster":  a.K8s.InCluster,
		"k8sConfigPath": a.K8s.ConfigPath,
		"natsNoop":      a.Nats.Noop,
		"natsAddress":   a.Nats.Address,
		"modules":       a.Modules,
	}).Info("info")

	hubbleRepo, err := hubblerepostiory.NewGRPC(rootCtx, a.Hubble.Address, []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())})
	if err != nil {
		return err
	}

	messagingRepo := messagingrepository.NewNoop[cisinapi.Connection]()

	if !a.Nats.Noop {
		messagingRepo, err = messagingrepository.NewNATS[cisinapi.Connection](a.Nats.Address)
		if err != nil {
			return err
		}
	}

	ciliumRepo, err := ciliumrepository.NewHTTP(a.Cilium.Address)
	if err != nil {
		return err
	}

	nodeName, err := os.Hostname()
	if err != nil {
		return err
	}

	if a.NodeName != "" {
		nodeName = a.NodeName
	}

	ifacesRepo, err := ifacesrepository.NewIfacesNet()
	if err != nil {
		return err
	}

	agentModules, err := a.getAgentModules(ifacesRepo)
	if err != nil {
		return err
	}

	ag, err := agent.NewAgent(a.ClusterName, nodeName, a.Nats.Subject, hubbleRepo, ciliumRepo, ifacesRepo, messagingRepo, agentModules...)
	if err != nil {
		return err
	}

	err = ag.Start(rootCtx)
	if err != nil {
		return err
	}

	<-sigChan

	return nil
}

func (a Agent) getK8sClientSet() (*kubernetes.Clientset, error) {
	var config *rest.Config

	var err error

	if a.K8s.InCluster {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	} else {
		configPath := a.K8s.ConfigPath

		if configPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}

			configPath = path.Join(home, ".kube", "config")
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, err
		}

		clientConfig, err := clientcmd.NewClientConfigFromBytes(data)
		if err != nil {
			return nil, err
		}

		config, err = clientConfig.ClientConfig()
		if err != nil {
			return nil, err
		}
	}

	k8sClientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return k8sClientSet, nil
}

func (a Agent) getAgentModules(ifacesRepo ifacesrepository.Ifaces) ([]agentmodule.AgentModule, error) {
	var agentModules []agentmodule.AgentModule

	var k8sClientSet *kubernetes.Clientset

	var err error

	if a.NodeType == "k8s" {
		k8sClientSet, err = a.getK8sClientSet()
		if err != nil {
			return nil, err
		}
	}

	for _, moduleName := range a.Modules {
		var module agentmodule.AgentModule

		switch moduleName {
		case agentmodule.K8sImageModuleName:
			if a.NodeType != "k8s" {
				logrus.WithField("name", moduleName).Infof("ignore module")
			}

			module, err = agentmodule.NewK8sImageModule(k8sClientSet)
			if err != nil {
				return nil, err
			}
		case agentmodule.K8sSBOMModuleName:
			if a.NodeType != "k8s" {
				logrus.WithField("name", moduleName).Infof("ignore module")
			}

			module, err = agentmodule.NewK8sSBOMModule(k8sClientSet)
			if err != nil {
				return nil, err
			}
		case agentmodule.VMProcModuleName:
			if a.NodeType != "vm" {
				logrus.WithField("name", moduleName).Infof("ignore module")
			}

			procRepo, err := procrepository.NewProcFS()
			if err != nil {
				return nil, err
			}

			module, err = agentmodule.NewVMProcModule(procRepo, ifacesRepo)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("module %s unknown", moduleName)
		}

		agentModules = append(agentModules, module)
	}

	return agentModules, nil
}
