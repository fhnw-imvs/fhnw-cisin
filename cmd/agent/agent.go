// Package agentcmd contains the command to start the agent
package agentcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/image/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent/agentcilium"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent/agentsbomhost"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent/agentsbomk8s"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agentmodule"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	containerdaemonrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/containerdaemon"
	hubblerepostiory "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/hubble"
	ifacesrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifaces"
	k8srepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/k8s"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	registryrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/registry"
	sbomrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/sbom"
	sbomhostservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/sbomhost"
	sbomservice "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/service/sbomimage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Agent is the command to start the CISIN agent.
type Agent struct {
	NodeName          string        `env:"CISIN_NODE_NAME"          help:"Agent hostname"              json:"nodeName"`
	ClusterName       string        `env:"CISIN_CLUSTER_NAME"       help:"Kubernetes cluster name"     json:"clusterName"                                required:""`
	NodeType          string        `default:"k8s"                  enum:"k8s,host"                    env:"CISIN_NODE_TYPE"                             help:"Supported node types (k8s, host)" json:"nodeType"`
	Hubble            hubble        `embed:""                       envprefix:"CISIN_HUBBLE_"          json:"hubble"                                     prefix:"hubble-"`
	Nats              nats          `embed:""                       envprefix:"CISIN_NATS_"            json:"nats"                                       prefix:"nats-"`
	K8s               k8s           `embed:""                       envprefix:"CISIN_K8S_"             json:"k8s"                                        prefix:"k8s-"`
	LogLevel          string        `default:"info"                 env:"CISIN_LOG_LEVEL"              help:"Log level to use"                           json:"logLevel"`
	SrcModules        []string      `default:"k8s_image,k8s_digest" env:"CISIN_SRC_MODULES"            help:"Agent modules for flow sources"             json:"srcModules"`
	DestModules       []string      `default:"k8s_image,k8s_digest" env:"CISIN_DEST_MODULES"           help:"Agent modules for flow destinations"        json:"destModules"`
	ImageSrc          string        `default:"containerd"           enum:"docker,containerd,registry"  env:"CISIN_IMAGE_SOURCE"                          help:"Image source"         json:"imageSrc"`
	ImageSrcNamespace string        `default:"k8s.io"               env:"CISIN_IMAGE_SOURCE_NAMESPACE" help:"Namespace for containerd image source"      json:"imageSrcNamespace"`
	Registry          registry      `embed:""                       envprefix:"CISIN_REGISTRY_"        json:"registry"                                   prefix:"registry-"`
	SBOM              sbom          `embed:""                       envprefix:"CISIN_SBOM_"            json:"sbom"                                       prefix:"sbom-"`
	CacheTTL          time.Duration `default:"30s"                  env:"CISIN_CACHE_TTL"              help:"Time before a message for a flow is resent" json:"cacheTTL"`
}

type registry struct {
	URL      string `default:"harbor.cisin.svc.cluster.local:80/cisin" env:"URL"                  help:"OCI registry URL"                       json:"url"`
	Username string `default:"cisin"                                   env:"USERNAME"             help:"OCI registry username"                  json:"username"`
	Secret   string `env:"SECRET"                                      help:"OCI registry secret" json:"secret"`
	Insecure bool   `default:"true"                                    env:"INSECURE"             help:"Do not use TLS to connect OCI registry" json:"insecure"`
}

type hubble struct {
	Address string `default:"unix:///var/run/cilium/hubble.sock" env:"ADDRESS" help:"Hubble address"                json:"address"`
	Subject string `default:"hubble"                             env:"SUBJECT" help:"NATS subject to publish flows" json:"subject"`
}

type nats struct {
	Address string `default:"localhost:4222" env:"ADDRESS" help:"NATS address"                          json:"address"`
	Noop    bool   `default:"false"          env:"NOOP"    help:"Do not publish messages to NATS queue" json:"noop"`
}

type sbom struct {
	GenerationInterval time.Duration `default:"30s"   env:"GENERATION_INTERVAL" help:"Interval to generate SBOMs"                   json:"generationInterval"`
	Subject            string        `default:"sbom"  env:"SUBJECT"             help:"NATS subject to publish SBOM information"     json:"subject"`
	FSRoot             string        `default:"/host" env:"FS_ROOT"             help:"Filesystem root to generate SBOMs on hosts"   json:"fsRoot"`
	Generate           bool          `default:"true"  env:"GENERATE"            help:"Generate SBOMs"                               json:"generate"`
	Insecure           bool          `default:"false" env:"INSECURE"            help:"Do not use TLS to retrieve SBOMs from remote" json:"insecure"`
}

type k8s struct {
	ConfigPath string `default:"/etc/kubernetes/admin.conf" env:"CONFIG_PATH" help:"Path to Kubernetes config"              json:"configPath"`
	InCluster  bool   `default:"true"                       env:"IN_CLUSTER"  help:"Use default Kubernetes config from pod" json:"inCluster"`
}

// Run executes the command
//
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

	// setup hubble repo
	hubbleRepo, err := hubblerepostiory.NewGRPC(rootCtx, a.Hubble.Address, []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())})
	if err != nil {
		return fmt.Errorf("hubble repo: %w", err)
	}

	// setup NATS connection
	connectionMessagingRepo := messagingrepository.NewNoop[cisinapi.Connection, *cisinapi.Connection]()
	sbomMessagingRepo := messagingrepository.NewNoop[cisinapi.Sbom, *cisinapi.Sbom]()

	if !a.Nats.Noop {
		connectionMessagingRepo, err = messagingrepository.NewNATS[cisinapi.Connection, *cisinapi.Connection](a.Nats.Address)
		if err != nil {
			return fmt.Errorf("new nats connection repo: %w", err)
		}

		sbomMessagingRepo, err = messagingrepository.NewNATS[cisinapi.Sbom, *cisinapi.Sbom](a.Nats.Address)
		if err != nil {
			return fmt.Errorf("new nats sbom repo: %w", err)
		}
	}

	// evaluate hostname
	nodeName, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}

	if a.NodeName != "" {
		nodeName = a.NodeName
	}

	// setup network interfaces repo
	ifacesRepo, err := ifacesrepository.NewIfacesNet()
	if err != nil {
		return fmt.Errorf("new ifaces repo: %w", err)
	}

	// setup agent modules for flow sources
	srcAgentModules, err := a.getAgentModules(a.SrcModules)
	if err != nil {
		return err
	}

	// setup agent modules for flow destinations
	destAgentModules, err := a.getAgentModules(a.DestModules)
	if err != nil {
		return err
	}

	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal options: %w", err)
	}

	logrus.WithField("data", data).Info("config")

	// setup agent for network traffic
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
		CacheTTL:                a.CacheTTL,
	})
	if err != nil {
		return fmt.Errorf("create agent: %w", err)
	}

	// setup agent for SBOM generation
	agentSbom, err := a.getAgentSBOM(nodeName, sbomMessagingRepo)
	if err != nil {
		return err
	}

	// start agent for network traffic
	logrus.Infof("start agent cilium")

	err = agentCilium.Start(rootCtx)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}

	// start agent for SBOM generation
	logrus.Infof("start agent sbom")

	err = agentSbom.Start(rootCtx)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}

	<-sigChan

	return nil
}

func (a Agent) getAgentSBOM(nodeName string, sbomMessagingRepo messagingrepository.Messaging[cisinapi.Sbom, *cisinapi.Sbom]) (agent.Agent, error) {
	switch a.NodeType {
	case constant.K8sNodeType:
		return a.getAgentSBOMK8s(sbomMessagingRepo)
	case constant.HostType:
		return a.getAgentSBOMHost(nodeName, sbomMessagingRepo)
	default:
		return nil, fmt.Errorf("node type %s is unknown: %w", a.NodeType, constant.ErrInvalid)
	}
}

func (a Agent) getAgentSBOMK8s(sbomMessagingRepo messagingrepository.Messaging[cisinapi.Sbom, *cisinapi.Sbom]) (agent.Agent, error) {
	sbomRepo := sbomrepository.NewSyftImageSBOM(a.getImageSrc(), func(namespace, ref string, insecure bool) image.Provider {
		return containerd.NewDaemonProvider(&file.TempDirGenerator{}, image.RegistryOptions{
			InsecureSkipTLSVerify: insecure,
		}, namespace, ref, &image.Platform{
			Architecture: runtime.GOARCH,
			OS:           runtime.GOOS,
		})
	}, a.ImageSrcNamespace, a.SBOM.Insecure)
	registryRepo := registryrepository.NewContainerRegistry(a.Registry.URL, a.Registry.Username, a.Registry.Secret, a.Registry.Insecure)

	containerDaemonRepo, err := containerdaemonrepository.NewContainerd(defaults.DefaultAddress, "k8s.io")
	if err != nil {
		return nil, fmt.Errorf("create container daemon repo: %w", err)
	}

	sbomService := sbomservice.New(containerDaemonRepo, registryRepo, sbomRepo)

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

func (a Agent) getAgentSBOMHost(nodeName string, sbomMessagingRepo messagingrepository.Messaging[cisinapi.Sbom, *cisinapi.Sbom]) (agent.Agent, error) {
	sbomRepo := sbomrepository.NewSyftFSSBOM()
	registryRepo := registryrepository.NewContainerRegistry(a.Registry.URL, a.Registry.Username, a.Registry.Secret, a.Registry.Insecure)
	sbomService := sbomhostservice.New(nodeName, registryRepo, sbomRepo)

	agentSBOM, err := agentsbomhost.NewAgent(agentsbomhost.Opts{
		SBOMHostSubject:        a.SBOM.Subject,
		SBOMHostMessagingRepo:  sbomMessagingRepo,
		SBOMService:            sbomService,
		SBOMGenerationInterval: a.SBOM.GenerationInterval,
		SBOMRoot:               a.SBOM.FSRoot,
	})
	if err != nil {
		return nil, fmt.Errorf("agent sbom host: %w", err)
	}

	return agentSBOM, nil
}

func (a Agent) getAgentModules(modules []string) ([]agentmodule.AgentModule, error) {
	agentModules := make([]agentmodule.AgentModule, 0)

	var k8sRepo k8srepository.K8s

	var err error

	if a.NodeType == constant.K8sNodeType {
		k8sRepo, err = k8srepository.NewK8sClientSet(a.K8s.InCluster, a.K8s.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("create k8s repository: %w", err)
		}
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
