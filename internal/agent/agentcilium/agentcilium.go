// Package agentcilium generates NATS messages base on Hubble socket
package agentcilium

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agent"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agentmodule"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/id"
	hubblerepostiory "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/hubble"
	ifacesrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifaces"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/safemap"
)

// Opts contains options.
type Opts struct {
	ClusterName             string
	NodeName                string
	NodeType                string
	ConnectionSubject       string
	HubbleRepo              hubblerepostiory.Hubble
	IfacesRepo              ifacesrepository.Ifaces
	ConnectionMessagingRepo messagingrepository.Messaging[cisinapi.Connection, *cisinapi.Connection]
	SrcAgentModules         []agentmodule.AgentModule
	DestAgentModules        []agentmodule.AgentModule
	CacheTTL                time.Duration
}

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

type agentCilium struct {
	Opts
	cacheTTLMap safemap.SafeMap[string, time.Time]
}

// NewAgent creates a Cilium agent.
func NewAgent(opts Opts) (agent.Agent, error) {
	return agentCilium{
		Opts:        opts,
		cacheTTLMap: safemap.NewSafeMap[string, time.Time](),
	}, nil
}

func (a agentCilium) Start(ctx context.Context) error {
	a.startHubble(ctx)

	return nil
}

func (a agentCilium) startHubble(ctx context.Context) {
	flowChan, errChan := a.HubbleRepo.StartFlowChannel(ctx)

	go func() {
		logger := logrus.WithField("type", "hubble")

		// receive hubble flows
		for {
			select {
			case <-ctx.Done():
			case receivedFlow := <-flowChan:
				logger.WithFields(logrus.Fields{
					"id":       receivedFlow.Flow.GetUuid(),
					"nodeName": receivedFlow.NodeName,
					"flow":     fmt.Sprintf("%v", receivedFlow),
				}).Tracef("hubble message")

				err := a.receiveHubbleMessage(receivedFlow)
				if err != nil {
					logger.Error(err)
				}
			case err := <-errChan:
				logger.Error(err)
			}
		}
	}()
}

func (a agentCilium) receiveHubbleMessage(receivedFlow *hubblerepostiory.Flow) error {
	// check if flow should be analyzed
	if a.skipAnalyze(receivedFlow) {
		return nil
	}

	// check if flow is cached
	cacheKey := fmt.Sprintf("%d-%d", receivedFlow.Flow.GetSource().GetIdentity(), receivedFlow.Flow.GetDestination().GetIdentity())

	logrus.WithFields(logrus.Fields{
		"id":       receivedFlow.Flow.GetUuid(),
		"cacheKey": cacheKey,
	}).Trace("analyze hubble message")

	if lastSent, ok := a.cacheTTLMap.Get(cacheKey); ok {
		if lastSent.Add(a.Opts.CacheTTL).After(time.Now()) {
			logrus.WithFields(logrus.Fields{
				"id":       receivedFlow.Flow.GetUuid(),
				"cacheKey": cacheKey,
			}).Trace("skip cached message")

			return nil
		}
	}

	// analyze flow source
	srcWorkload, err := a.analyseEndpoint(receivedFlow.Flow.GetUuid(), receivedFlow.Flow.GetIP().GetSource(), int(receivedFlow.Flow.GetL4().GetTCP().GetSourcePort()), receivedFlow.Flow.GetSource(), a.SrcAgentModules)
	if err != nil {
		return err
	}

	// analyze flow destination - this analysis is simpler than the analysis from src workload, because the destination is probably not on
	// the same host as the agent is running
	dstWorkload, err := a.analyseEndpoint(receivedFlow.Flow.GetUuid(), receivedFlow.Flow.GetIP().GetDestination(), int(receivedFlow.Flow.GetL4().GetTCP().GetDestinationPort()), receivedFlow.Flow.GetDestination(), a.DestAgentModules)
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"id":       receivedFlow.Flow.GetUuid(),
		"cacheKey": cacheKey,
	}).Trace("send analyzed hubble message")

	// publish analysis result to NATS
	err = a.ConnectionMessagingRepo.Send(a.ConnectionSubject, &cisinapi.Connection{
		Source:      srcWorkload,
		Destination: dstWorkload,
		Host:        a.NodeName,
	})
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	// add message to cache
	a.cacheTTLMap.Set(cacheKey, time.Now())

	return nil
}

//nolint:funlen // log statements
func (a agentCilium) skipAnalyze(receivedFlow *hubblerepostiory.Flow) bool {
	// check if flow belongs to this host
	if receivedFlow.NodeName != fmt.Sprintf("%s/%s", a.ClusterName, a.NodeName) {
		logrus.WithFields(logrus.Fields{
			"id":       receivedFlow.Flow.GetUuid(),
			"reason":   "node name mismatch",
			"received": receivedFlow.NodeName,
			"expected": fmt.Sprintf("%s/%s", a.ClusterName, a.NodeName),
		}).Tracef("skip hubble message")

		return true
	}

	// check if flow is nil
	if receivedFlow.Flow == nil {
		logrus.WithFields(logrus.Fields{
			"id":     receivedFlow.Flow.GetUuid(),
			"reason": "flow is nil",
		}).Tracef("skip hubble message")

		return true
	}

	// check if flow is reply
	if receivedFlow.Flow.GetIsReply().GetValue() {
		logrus.WithFields(logrus.Fields{
			"id":     receivedFlow.Flow.GetUuid(),
			"reason": "is reply",
		}).Tracef("skip hubble message")

		return true
	}

	// check if TCP information is set
	if receivedFlow.Flow.GetL4().GetTCP() == nil {
		logrus.WithFields(logrus.Fields{
			"id":     receivedFlow.Flow.GetUuid(),
			"reason": "tcp is nil",
		}).Tracef("skip hubble message")

		return true
	}

	// check if IP information is set
	if receivedFlow.Flow.GetIP() == nil {
		logrus.WithFields(logrus.Fields{
			"id":     receivedFlow.Flow.GetUuid(),
			"reason": "ip is nil",
		}).Tracef("skip hubble message")

		return true
	}

	// check if source is not empty
	if receivedFlow.Flow.GetSource() == nil {
		logrus.WithFields(logrus.Fields{
			"id":     receivedFlow.Flow.GetUuid(),
			"reason": "source is nil",
		}).Tracef("skip hubble message")

		return true
	}

	// check if source port is in ephemeral range - on external workload replies are not always recognized properly ->
	// to distinct between request and reply, we assume requests have ephemeral port as source port
	if receivedFlow.Flow.GetL4().GetTCP().GetSourcePort() < constant.EphemeralPortStart {
		logrus.WithFields(logrus.Fields{
			"id":       receivedFlow.Flow.GetUuid(),
			"reason":   "source port is not in ephemeral range",
			"received": receivedFlow.Flow.GetL4().GetTCP().GetSourcePort(),
			"expected": " >= 32768",
		}).Tracef("skip hubble message")

		return true
	}

	// check if destination is not empty
	if receivedFlow.Flow.GetDestination() == nil {
		logrus.WithFields(logrus.Fields{
			"id":     receivedFlow.Flow.GetUuid(),
			"reason": "destination is nil",
		}).Tracef("skip hubble message")

		return true
	}

	return false
}

//nolint:cyclop
func (a agentCilium) analyseEndpoint(uuid, ipAddress string, port int, endpoint *observer.Endpoint, modules []agentmodule.AgentModule) (*cisinapi.Workload, error) {
	var err error

	cisinWorkload := &cisinapi.Workload{
		Id: constant.WorldID,
	}

	switch {
	case slices.Contains(endpoint.GetLabels(), labelReservedWorld):
		cisinWorkload.Type = cisinapi.WorkloadType_WORLD
	case slices.Contains(endpoint.GetLabels(), labelReservedHost):
	case slices.Contains(endpoint.GetLabels(), labelReservedRemoteNode):
	case slices.Contains(endpoint.GetLabels(), fmt.Sprintf("%s=%s", labelCluster, a.ClusterName)) && slices.Contains(endpoint.GetLabels(), fmt.Sprintf("%s=%s", labelPod, a.NodeName)):
		cisinWorkload.Type = cisinapi.WorkloadType_HOST
		cisinWorkload.Id = id.GetExternalWorkloadID(a.NodeName)
	case slices.Contains(endpoint.GetLabels(), labelReservedHealth):
	case slices.Contains(endpoint.GetLabels(), labelReservedIngress):
	case slices.Contains(endpoint.GetLabels(), labelReservedInit):
	case slices.Contains(endpoint.GetLabels(), labelReservedKubeApisServer):
	case slices.Contains(endpoint.GetLabels(), labelReservedUnknown):
	case slices.Contains(endpoint.GetLabels(), labelReservedUnmanaged):
	default:
		cisinWorkload.Type = cisinapi.WorkloadType_KUBERNETES

		cisinWorkload.Id, err = id.GetK8sID(endpoint)
		if err != nil {
			return nil, fmt.Errorf("get id: %w", err)
		}
	}

	analyseMap, err := a.analyze(ipAddress, port, endpoint, modules)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"id":       uuid,
			"endpoint": "source",
		}).Error(err)
	}

	cisinWorkload.Results = analyseMap

	return cisinWorkload, nil
}

func (a agentCilium) analyze(ipAddr string, port int, e *flow.Endpoint, modules []agentmodule.AgentModule) (map[string]*cisinapi.Analyse, error) {
	analyseMap := make(map[string]*cisinapi.Analyse)

	for _, module := range modules {
		analyze, err := module.Analyze(ipAddr, port, e)
		if err != nil {
			return nil, fmt.Errorf("analyze module %s: %w", module.ModuleName(), err)
		}

		if analyze == nil {
			continue
		}

		analyseMap[module.ModuleName()] = analyze
	}

	return analyseMap, nil
}
