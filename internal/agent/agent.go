package agent

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agentmodule"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/id"
	ciliumrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/cilium"
	hubblerepostiory "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/hubble"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifacesrepository"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"slices"
)

type Agent interface {
	Start(ctx context.Context) error
}

type nodeType string

const nodeTypeK8s = "k8s"

const (
	labelReservedUnknown        = "reserved:unknown"
	labelReservedHost           = "reserved:host"
	labelReservedWorld          = "reserved:world"
	labelReservedUnmanaged      = "reserved:unmanaged"
	labelReservedHealth         = "reserved:health"
	labelReservedInit           = "reserved:init"
	labelReservedRemoteNode     = "reserved:remote-node"
	labelReservedKubeApisServer = "reserved:kube-apiserver"
	labelReservedIngress        = "reserved:ingress"
	labelCluster                = "k8s:io.cilium.k8s.policy.cluster"
	labelPod                    = "k8s:io.kubernetes.pod.name"
)

type agent struct {
	hubbleRepo    hubblerepostiory.Hubble
	ifacesRepo    ifacesrepository.Ifaces
	messagingRepo messagingrepository.Messaging[cisinapi.Connection]
	ciliumRepo    ciliumrepository.Cilium
	nodeName      string
	clusterName   string
	modules       []agentmodule.AgentModule
	nodeType      nodeType
	subject       string
}

func NewAgent(clusterName, nodeName, subject string, hubbleRepo hubblerepostiory.Hubble, ciliumRepo ciliumrepository.Cilium, ifacesRepo ifacesrepository.Ifaces, messagingRepo messagingrepository.Messaging[cisinapi.Connection], agentModules ...agentmodule.AgentModule) (Agent, error) {
	return agent{
		hubbleRepo:    hubbleRepo,
		messagingRepo: messagingRepo,
		ciliumRepo:    ciliumRepo,
		ifacesRepo:    ifacesRepo,
		nodeName:      nodeName,
		clusterName:   clusterName,
		modules:       agentModules,
		nodeType:      nodeTypeK8s,
	}, nil
}

func (a agent) Start(ctx context.Context) error {
	flowChan, errChan := a.hubbleRepo.StartFlowChannel(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
			case f := <-flowChan:
				srcWorkload := &cisinapi.Workload{}
				dstWorkload := &cisinapi.Workload{}

				var err error

				logrus.WithField("nodeName", f.NodeName).Tracef("hubble message")

				if f.NodeName != fmt.Sprintf("%s/%s", a.clusterName, a.nodeName) {
					continue
				}

				if f.Flow == nil {
					continue
				}

				if f.Flow.GetIsReply().GetValue() {
					continue
				}

				if f.Flow.L4.GetTCP() == nil {
					continue
				}

				if f.Flow.GetIP() == nil {
					continue
				}

				if f.Flow.GetSource() != nil {
					srcWorkload, err = a.analyseEndpoint(f.Flow.GetIP().GetSource(), int(f.Flow.GetL4().GetTCP().GetSourcePort()), f.Flow.GetSource())
					if err != nil {
						logrus.Error(err)
						continue
					}
				}

				if f.Flow.GetDestination() != nil {
					dstWorkload, err = a.analyseEndpoint(f.Flow.GetIP().GetDestination(), int(f.Flow.GetL4().GetTCP().GetDestinationPort()), f.Flow.GetDestination())
					if err != nil {
						logrus.Error(err)
						continue
					}
				}

				err = a.messagingRepo.Send(a.subject, &cisinapi.Connection{
					Source:      srcWorkload,
					Destination: dstWorkload,
				})
				if err != nil {
					logrus.Error(err)
				}
			case err := <-errChan:
				logrus.Error(err)
			}
		}
	}()

	return nil
}

func (a agent) analyseEndpoint(ipAddress string, port int, e *observer.Endpoint) (*cisinapi.Workload, error) {
	var err error

	w := &cisinapi.Workload{
		Id: constant.WorldID,
	}

	switch {
	case slices.Contains(e.GetLabels(), labelReservedWorld):
		w.Type = cisinapi.WorkloadType_WORLD
	case slices.Contains(e.GetLabels(), labelReservedHost):
		// TODO: Distinct between Java and Docker
		w.Type = cisinapi.WorkloadType_DOCKER
		w.Id, err = id.GetVmID(ipAddress, a.ifacesRepo)
		if err != nil {
			return nil, err
		}
	case slices.Contains(e.GetLabels(), labelReservedRemoteNode):
		// TODO: Distinct between Java and Docker
		w.Type = cisinapi.WorkloadType_DOCKER
		w.Id, err = id.GetVmID(ipAddress, a.ifacesRepo)
		if err != nil {
			return nil, err
		}
		// TODO: Not 100% secure
	case slices.Contains(e.GetLabels(), fmt.Sprintf("%s=%s", labelCluster, a.clusterName)) && slices.Contains(e.GetLabels(), fmt.Sprintf("%s=%s", labelPod, a.nodeName)):
		w.Type = cisinapi.WorkloadType_DOCKER
		w.Id = a.nodeName
	case slices.Contains(e.GetLabels(), labelReservedHealth):
	case slices.Contains(e.GetLabels(), labelReservedIngress):
	case slices.Contains(e.GetLabels(), labelReservedInit):
	case slices.Contains(e.GetLabels(), labelReservedKubeApisServer):
	case slices.Contains(e.GetLabels(), labelReservedUnknown):
	case slices.Contains(e.GetLabels(), labelReservedUnmanaged):
	default:
		w.Type = cisinapi.WorkloadType_KUBERNETES
		w.Id, err = id.GetK8sID(e)
		if err != nil {
			return nil, err
		}
	}

	// TODO: Watch Cilium external resources to check if target is VM or K8s

	analyseMap, err := a.analyze(ipAddress, port, e)
	if err != nil {
		logrus.WithField("endpoint", "source").Error(err)
	}

	w.Results = analyseMap

	return w, nil
}

func (a agent) analyze(ipAddr string, port int, e *flow.Endpoint) (map[string]*cisinapi.Analyse, error) {
	analyseMap := make(map[string]*cisinapi.Analyse)

	for _, module := range a.modules {
		analyze, err := module.Analyze(ipAddr, port, e)
		if err != nil {
			return nil, err
		}

		if analyze == nil {
			continue
		}

		analyseMap[module.ModuleName()] = analyze
	}

	return analyseMap, nil
}
