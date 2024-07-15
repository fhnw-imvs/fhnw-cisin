package agentcmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/containerd/containerd/defaults"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent/agentcilium"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent/agentsbomk8s"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent/agentsbomvm"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agentmodule"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/k8sclient"
	containerdaemonrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/containerdaemon"
	hubblerepostiory "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/hubble"
	ifacesrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifaces"
	k8srepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/k8s"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	registryrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/registry"
	sbomrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/sbom"
	sbomservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/sbom"
	sbomvmservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/sbomvm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Agent struct {
	NodeName          string        `env:"NODE_NAME"`
	ClusterName       string        `required:""`
	NodeType          string        `default:"k8s"                  enum:"k8s,vm"`
	Hubble            hubble        `embed:""                       prefix:"hubble-"`
	Nats              nats          `embed:""                       prefix:"nats-"`
	K8s               k8s           `embed:""                       prefix:"k8s-"`
	Cilium            cilium        `embed:""                       prefix:"cilium-"`
	LogLevel          string        `default:"info"`
	SrcModules        []string      `default:"k8s_image,k8s_digest"`
	DestModules       []string      `default:"k8s_image,k8s_digest"`
	ImageSrc          string        `default:"containerd"           enum:"docker,containerd,registry"`
	ImageSrcNamespace string        `default:"k8s.io"`
	Registry          registry      `embed:""                       prefix:"registry-"`
	SBOM              sbom          `embed:""                       prefix:"sbom-"`
	CachdTTL          time.Duration `default:"30s"`
}

type registry struct {
	URL      string `default:"harbor.cisin.svc.cluster.local:80/cisin"`
	Username string `default:"cisin"`
	Secret   string `env:"REGISTRY_SECRET"`
	Insecure bool   `default:"true"`
}

type hubble struct {
	Address string `default:"unix:///var/run/cilium/hubble.sock"`
	Subject string `default:"hubble"`
}

type cilium struct {
	Address string `default:"unix:///var/run/cilium/cilium.sock"`
}

type nats struct {
	Address string `default:"localhost:4222"`
	Noop    bool   `default:"false"`
}

type sbom struct {
	GenerationInterval time.Duration `default:"30s"`
	Subject            string        `default:"sbom"`
	VMSubject          string        `default:"sbomvm"`
	VMSBOMRoot         string        `default:"/host"`
	Generate           bool          `default:"true"`
	Insecure           bool          `default:"false"`
}

type k8s struct {
	ConfigPath string
	InCluster  bool
}

//nolint:funlen,cyclop
func (a Agent) Run() error {
	sigChan := make(chan os.Signal, 1)
	rootCtx, cancel := context.WithCancel(context.Background())

	defer cancel()

	signal.Notify(sigChan, os.Interrupt)

	level, err := logrus.ParseLevel(a.LogLevel)
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	logrus.SetLevel(level)

	hubbleRepo, err := hubblerepostiory.NewGRPC(rootCtx, a.Hubble.Address, []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())})
	if err != nil {
		return fmt.Errorf("hubble repo: %w", err)
	}

	connectionMessagingRepo := messagingrepository.NewNoop[cisinapi.Connection, *cisinapi.Connection]()

	if !a.Nats.Noop {
		connectionMessagingRepo, err = messagingrepository.NewNATS[cisinapi.Connection, *cisinapi.Connection](a.Nats.Address)
		if err != nil {
			return fmt.Errorf("new nats connection repo: %w", err)
		}
	}

	nodeName, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}

	if a.NodeName != "" {
		nodeName = a.NodeName
	}

	ifacesRepo, err := ifacesrepository.NewIfacesNet()
	if err != nil {
		return fmt.Errorf("new ifaces repo: %w", err)
	}

	srcAgentModules, err := a.getAgentModules(a.SrcModules)
	if err != nil {
		return err
	}

	destAgentModules, err := a.getAgentModules(a.DestModules)
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"nodeName":      nodeName,
		"clusterName":   a.ClusterName,
		"nodeType":      a.NodeType,
		"hubbleAddress": a.Hubble.Address,
		"ciliumAddress": a.Cilium.Address,
		"k8sInCluster":  a.K8s.InCluster,
		"k8sConfigPath": a.K8s.ConfigPath,
		"natsNoop":      a.Nats.Noop,
		"natsAddress":   a.Nats.Address,
		"natsSubject":   a.Hubble.Subject,
		"modules":       a.SrcModules,
	}).Info("info")

	agentCilium, err := agentcilium.NewAgent(agentcilium.Opts{
		ClusterName:             a.ClusterName,
		NodeName:                nodeName,
		NodeType:                a.NodeType,
		ConnectionSubject:       a.Hubble.Subject,
		HubbleRepo:              hubbleRepo,
		IfacesRepo:              ifacesRepo,
		ConnectionMessagingRepo: connectionMessagingRepo,
		SrcAgentModules:         srcAgentModules,
		DestAgentModules:        destAgentModules,
		CacheTTL:                a.CachdTTL,
	})
	if err != nil {
		return fmt.Errorf("create agent: %w", err)
	}

	agentSbom, err := a.getAgentSBOM(nodeName)
	if err != nil {
		return err
	}

	logrus.Infof("start agent cilium")

	err = agentCilium.Start(rootCtx)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}

	logrus.Infof("start agent sbom")

	err = agentSbom.Start(rootCtx)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}

	<-sigChan

	return nil
}

func (a Agent) getAgentSBOM(nodeName string) (agent.Agent, error) {
	switch a.NodeType {
	case constant.K8sNodeType:
		return a.getAgentSBOMK8s()
	case constant.VMNodeType:
		return a.getAgentSBOMVM(nodeName)
	default:
		return nil, fmt.Errorf("node type %s is unknown: %w", a.NodeType, constant.ErrInvalid)
	}
}

func (a Agent) getAgentSBOMK8s() (agent.Agent, error) {
	sbomRepo := sbomrepository.NewSyftSBOM(a.getImageSrc(), a.ImageSrcNamespace, a.SBOM.Insecure)
	registryRepo := registryrepository.NewContainerRegistry(a.Registry.URL, a.Registry.Username, a.Registry.Secret, a.Registry.Insecure)

	containerDaemonRepo, err := containerdaemonrepository.NewContainerd(defaults.DefaultAddress, "k8s.io")
	if err != nil {
		return nil, fmt.Errorf("create container daemon repo: %w", err)
	}

	sbomService := sbomservice.New(containerDaemonRepo, registryRepo, sbomRepo)
	sbomMessagingRepo := messagingrepository.NewNoop[cisinapi.Sbom, *cisinapi.Sbom]()

	if !a.Nats.Noop {
		sbomMessagingRepo, err = messagingrepository.NewNATS[cisinapi.Sbom, *cisinapi.Sbom](a.Nats.Address)
		if err != nil {
			return nil, fmt.Errorf("new nats sbom repo: %w", err)
		}
	}

	agentSBOM, err := agentsbomk8s.NewAgent(agentsbomk8s.Opts{
		SBOMSubject:            a.SBOM.Subject,
		SBOMMessagingRepo:      sbomMessagingRepo,
		ContainerDaemonRepo:    containerDaemonRepo,
		SBOMService:            sbomService,
		SBOMGenerationInterval: a.SBOM.GenerationInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("agent sbom k8s: %w", err)
	}

	return agentSBOM, nil
}

func (a Agent) getAgentSBOMVM(nodeName string) (agent.Agent, error) {
	sbomRepo := sbomrepository.NewSyftFSSBOM()
	registryRepo := registryrepository.NewContainerRegistry(a.Registry.URL, a.Registry.Username, a.Registry.Secret, a.Registry.Insecure)
	sbomService := sbomvmservice.New(nodeName, registryRepo, sbomRepo)
	sbomVMMessagingRepo := messagingrepository.NewNoop[cisinapi.SbomVM, *cisinapi.SbomVM]()

	var err error

	if !a.Nats.Noop {
		sbomVMMessagingRepo, err = messagingrepository.NewNATS[cisinapi.SbomVM, *cisinapi.SbomVM](a.Nats.Address)
		if err != nil {
			return nil, fmt.Errorf("new nats sbom repo: %w", err)
		}
	}

	agentSBOM, err := agentsbomvm.NewAgent(agentsbomvm.Opts{
		SBOMVMSubject:          a.SBOM.VMSubject,
		SBOMVMMessagingRepo:    sbomVMMessagingRepo,
		SBOMService:            sbomService,
		SBOMGenerationInterval: a.SBOM.GenerationInterval,
		SBOMRoot:               a.SBOM.VMSBOMRoot,
	})
	if err != nil {
		return nil, fmt.Errorf("agent sbom vm: %w", err)
	}

	return agentSBOM, nil
}

func (a Agent) getAgentModules(modules []string) ([]agentmodule.AgentModule, error) {
	agentModules := make([]agentmodule.AgentModule, 0)

	var k8sRepo k8srepository.K8s

	if a.NodeType == constant.K8sNodeType {
		k8sClientSet, err := k8sclient.GetK8sClientSet(a.K8s.InCluster, a.K8s.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("get k8s client: %w", err)
		}

		k8sRepo = k8srepository.New(k8sClientSet)
	}

	for _, moduleName := range modules {
		module, err := a.getModule(moduleName, k8sRepo)
		if err != nil {
			return nil, err
		}

		if module == nil {
			continue
		}

		agentModules = append(agentModules, module)
	}

	return agentModules, nil
}

func (a Agent) getModule(moduleName string, k8sRepo k8srepository.K8s) (agentmodule.AgentModule, error) {
	switch moduleName {
	case agentmodule.K8sImageModuleName:
		if a.NodeType != constant.K8sNodeType {
			logrus.WithField("name", moduleName).Infof("ignore module")

			//nolint:nilnil
			return nil, nil
		}

		module, err := agentmodule.NewK8sImageModule(k8sRepo)
		if err != nil {
			return nil, fmt.Errorf("create k8s image module: %w", err)
		}

		return module, nil
	case agentmodule.K8sDigestModuleName:
		if a.NodeType != constant.K8sNodeType {
			logrus.WithField("name", moduleName).Infof("ignore module")

			//nolint:nilnil
			return nil, nil
		}

		module, err := agentmodule.NewK8sDigestModule(k8sRepo)
		if err != nil {
			return nil, fmt.Errorf("create k8s digest module: %w", err)
		}

		return module, nil
	default:
		return nil, fmt.Errorf("module %s: %w", moduleName, constant.ErrUnknown)
	}
}

func (a Agent) getImageSrc() image.Source {
	switch a.ImageSrc {
	case "docker":
		return image.DockerDaemonSource
	case "registry":
		return image.OciRegistrySource
	default:
		return image.ContainerdDaemonSource
	}
}
