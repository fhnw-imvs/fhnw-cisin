package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/gammazero/workerpool"
	"github.com/sirupsen/logrus"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/agentmodule"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/id"
	k8srepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/k8s"
	messagingrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/messaging"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/tracing"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/safemap"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type Server interface {
	Start(ctx context.Context) error
}

type server struct {
	Opts
	Neighbourhood safemap.SafeMap[string, []neighbour]
	Participants  safemap.SafeMap[string, endpoint]
	IDToSBOMURl   safemap.SafeMap[string, string]
}

type Opts struct {
	ConnectionMessagingRepo messagingrepository.Messaging[cisinapi.Connection, *cisinapi.Connection]
	SBOMMessagingRepo       messagingrepository.Messaging[cisinapi.Sbom, *cisinapi.Sbom]
	SBOMVMMessagingRepo     messagingrepository.Messaging[cisinapi.SbomVM, *cisinapi.SbomVM]
	TracingRepo             tracing.Tracing
	WpSize                  int
	WpMaxQueueSize          int
	ConnectionSubject       string
	SBOMSubject             string
	SBOMVMSubject           string
	ConnectionQueue         string
	SBOMQueue               string
	SBOMVMQueue             string
	K8sRepo                 k8srepository.K8s
}

func NewServer(opts Opts) Server {
	return server{
		Opts:          opts,
		Neighbourhood: safemap.NewSafeMap[string, []neighbour](),
		Participants:  safemap.NewSafeMap[string, endpoint](),
		IDToSBOMURl:   safemap.NewSafeMap[string, string](),
	}
}

type endpoint struct {
	id          string
	srcResults  map[string]*cisinapi.Analyse
	destResults map[string]*cisinapi.Analyse
	timestamp   time.Time
}

type neighbour struct {
	id        string
	timestamp time.Time
}

func (s server) Start(ctx context.Context) error {
	err := s.startSBOM(ctx)
	if err != nil {
		return err
	}

	err = s.startTracing(ctx)
	if err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}

func (s server) startSBOM(ctx context.Context) error {
	for range s.WpSize {
		sbomChan, err := s.SBOMMessagingRepo.Receive(ctx, s.SBOMSubject, s.SBOMQueue)
		if err != nil {
			return fmt.Errorf("create sbom chan:%w", err)
		}

		sbomVMChan, err := s.SBOMVMMessagingRepo.Receive(ctx, s.SBOMVMSubject, s.SBOMVMQueue)
		if err != nil {
			return fmt.Errorf("create sbom chan:%w", err)
		}

		go func() {
			for sbom := range sbomChan {
				s.IDToSBOMURl.Set(sbom.GetDigest(), sbom.GetUrl())

				logrus.WithField("type", "sbom").Tracef("message received")
			}
		}()

		go func() {
			for sbom := range sbomVMChan {
				s.IDToSBOMURl.Set(sbom.GetHostname(), sbom.GetUrl())

				logrus.WithField("type", "sbomvm").Tracef("message received")
			}
		}()
	}

	return nil
}

func (s server) startTracing(ctx context.Context) error {
	logger := logrus.WithField("type", "connection")

	go func() {
		s.tracing(ctx)
	}()

	wp := workerpool.New(s.WpSize)

	for range s.WpSize {
		connectionChan, err := s.ConnectionMessagingRepo.Receive(ctx, s.ConnectionSubject, s.ConnectionQueue)
		if err != nil {
			return fmt.Errorf("create connection chan: %w", err)
		}

		go func() {
			for connection := range connectionChan {
				if wp.WaitingQueueSize() >= s.WpMaxQueueSize {
					logger.WithField("size", wp.WaitingQueueSize()).Warn("skip message due to full worker")
				}

				wp.Submit(func() {
					err := s.receiveConnectionMessage(ctx, connection)
					if err != nil {
						logger.Error(err)
					}
				})

				logger.WithField("size", wp.WaitingQueueSize()).Trace("wp queue size")
			}
		}()
	}

	return nil
}

func (s server) receiveConnectionMessage(ctx context.Context, connection *cisinapi.Connection) error {
	logger := logrus.WithField("type", "connection")
	src := connection.GetSource()
	dest := connection.GetDestination()
	now := time.Now()

	srcID, err := s.translateWorkloadID(ctx, src.GetId())
	if err != nil {
		return err
	}

	destID, err := s.translateWorkloadID(ctx, dest.GetId())
	if err != nil {
		return err
	}

	existingSrc, _ := s.Participants.Get(srcID)
	existingDest, _ := s.Participants.Get(destID)

	s.Participants.Set(srcID, endpoint{
		id:          srcID,
		srcResults:  src.GetResults(),
		destResults: existingSrc.destResults,
		timestamp:   now,
	})

	s.Participants.Set(destID, endpoint{
		id:          destID,
		srcResults:  existingDest.srcResults,
		destResults: dest.GetResults(),
		timestamp:   now,
	})

	neighbourhood, _ := s.Neighbourhood.Get(srcID)

	neighbourIndex := slices.IndexFunc(neighbourhood, func(n neighbour) bool {
		return n.id == destID
	})

	if neighbourIndex == -1 {
		neighbourhood = append(neighbourhood, neighbour{
			id:        destID,
			timestamp: now,
		})
	} else {
		neighbourhood[neighbourIndex] = neighbour{
			id:        destID,
			timestamp: now,
		}
	}

	s.Neighbourhood.Set(srcID, neighbourhood)

	logger.Trace("message received")

	return nil
}

func (s server) tracing(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.buildTraces(ctx)
		}
	}
}

func (s server) buildTraces(ctx context.Context) {
	keys := s.Neighbourhood.Keys()

	debugMap := make(map[string][]string)

	for _, key := range keys {
		value, ok := s.Neighbourhood.Get(key)
		if !ok {
			continue
		}

		for _, n := range value {
			debugMap[key] = append(debugMap[key], n.id)
		}
	}

	data, err := json.Marshal(debugMap)
	if err != nil {
		logrus.Error(err)
	} else {
		logrus.WithField("data", string(data)).Debugf("generate tracing")
	}

	roots := s.findRoots()

	worldNeighbours, _ := s.Neighbourhood.Get(constant.WorldID)

	for _, root := range roots {
		if root == constant.WorldID {
			continue
		}

		isWorldNeighbour := slices.ContainsFunc(worldNeighbours, func(n neighbour) bool {
			return n.id == root
		})

		if !isWorldNeighbour {
			s.buildTrace(ctx, root, nil)

			continue
		}

		logrus.Debugf("world neighbour")

		var span trace.Span

		ctx, span = s.TracingRepo.GetProvider().Tracer("cisin").Start(ctx, constant.WorldID)

		s.buildTrace(ctx, root, []string{constant.WorldID})

		span.End()
	}
}

//nolint:funlen,cyclop
func (s server) buildTrace(ctx context.Context, id string, idsInTrace []string) {
	var span trace.Span

	idsInTrace = append(idsInTrace, id)

	//nolint:varnamelen
	participant, ok := s.Participants.Get(id)
	if !ok {
		return
	}

	attributes := make([]attribute.KeyValue, 0)

	digests := make([]string, 0)

	for moduleName, analyse := range participant.destResults {
		attributes = append(attributes, attribute.KeyValue{
			Key:   attribute.Key(moduleName),
			Value: attribute.StringSliceValue(analyse.GetResults()),
		})

		if moduleName == agentmodule.K8sDigestModuleName {
			digests = analyse.GetResults()
		}
	}

	for moduleName, analyse := range participant.srcResults {
		i := slices.IndexFunc(attributes, func(value attribute.KeyValue) bool {
			return string(value.Key) == moduleName
		})

		if i > -1 {
			attributes[i] = attribute.KeyValue{
				Key:   attribute.Key(moduleName),
				Value: attribute.StringSliceValue(analyse.GetResults()),
			}
		} else {
			attributes = append(attributes, attribute.KeyValue{
				Key:   attribute.Key(moduleName),
				Value: attribute.StringSliceValue(analyse.GetResults()),
			})
		}

		if moduleName == agentmodule.K8sDigestModuleName {
			digests = analyse.GetResults()
		}
	}

	sboms := s.getSBOMsFromResults(digests)
	attributes = append(attributes, attribute.KeyValue{
		Key:   constant.SBOMsTraceTag,
		Value: attribute.StringSliceValue(sboms),
	})

	ctx, span = s.TracingRepo.GetProvider().Tracer("cisin").Start(ctx, id, trace.WithAttributes(attributes...))

	defer span.End()

	if id == constant.WorldID {
		return
	}

	neighbourhood, ok := s.Neighbourhood.Get(id)
	if !ok {
		return
	}

	for _, n := range neighbourhood {
		if slices.Contains(idsInTrace, n.id) {
			continue
		}

		s.buildTrace(ctx, n.id, idsInTrace)
	}
}

func (s server) translateWorkloadID(ctx context.Context, workloadID string) (string, error) {
	namespace, kind, name, err := id.ParseID(workloadID)
	if err != nil {
		return "", fmt.Errorf("parse id: %w", err)
	}

	if kind != "Pod" {
		return workloadID, nil
	}

	pod, err := s.K8sRepo.GetPod(ctx, name, namespace)
	if err != nil {
		return "", fmt.Errorf("get pod %s from namespace %s: %w", name, namespace, err)
	}

	if len(pod.OwnerReferences) == 0 {
		return workloadID, nil
	}

	if pod.OwnerReferences[0].Kind != "ReplicaSet" {
		return fmt.Sprintf("%s/%s/%s", namespace, pod.OwnerReferences[0].Kind, pod.OwnerReferences[0].Name), nil
	}

	replicaSet, err := s.K8sRepo.GetReplicaSet(ctx, pod.OwnerReferences[0].Name, namespace)
	if err != nil {
		return "", fmt.Errorf("create k8s clientset: %w", err)
	}

	if len(replicaSet.OwnerReferences) == 0 {
		return fmt.Sprintf("%s/%s/%s", namespace, replicaSet.Kind, replicaSet.Name), nil
	}

	return fmt.Sprintf("%s/%s/%s", namespace, replicaSet.OwnerReferences[0].Kind, replicaSet.OwnerReferences[0].Name), nil
}

func (s server) findRoots() []string {
	roots := make([]string, 0)
	keys := s.Neighbourhood.Keys()

	for _, key := range keys {
		root := true

		for _, potentialCallee := range keys {
			if key == potentialCallee {
				continue
			}

			potentialCalleesNeighbours, ok := s.Neighbourhood.Get(potentialCallee)
			if !ok {
				continue
			}

			if slices.ContainsFunc(potentialCalleesNeighbours, func(n neighbour) bool {
				if n.id == constant.WorldID {
					return false
				}

				return n.id == key
			}) {
				root = false
			}
		}

		if root {
			roots = append(roots, key)
		}
	}

	return roots
}

func (s server) getSBOMsFromResults(digests []string) []string {
	sboms := make([]string, len(digests))

	for i, result := range digests {
		sbom, _ := s.IDToSBOMURl.Get(result)

		sboms[i] = sbom
	}

	return sboms
}
