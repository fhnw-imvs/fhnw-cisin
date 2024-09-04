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

// Package server contains the server part of CISIN
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
	"k8s.io/apimachinery/pkg/api/errors"
)

// Server is the interface for a server.
type Server interface {
	// Start starts the server
	Start(ctx context.Context) error
}

type server struct {
	Opts
	Neighbourhood safemap.SafeMap[string, []neighbour]
	Participants  safemap.SafeMap[string, endpoint]
	IDToSBOMURl   safemap.SafeMap[string, string]
}

// Opts contains options.
type Opts struct {
	ConnectionMessagingRepo messagingrepository.Messaging[cisinapi.Connection, *cisinapi.Connection]
	SBOMMessagingRepo       messagingrepository.Messaging[cisinapi.Sbom, *cisinapi.Sbom]
	TracingRepo             tracing.Tracing
	WpSize                  int
	WpMaxQueueSize          int
	ConnectionSubject       string
	SBOMSubject             string
	ConnectionQueue         string
	SBOMQueue               string
	K8sRepo                 k8srepository.K8s
	ExcludeWorkloads        []string
}

// NewServer creates a new Server.
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
	// starz SBOM part
	err := s.startSBOM(ctx)
	if err != nil {
		return err
	}

	// start tracing part
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

		// receive SBOM messages
		go func() {
			for sbom := range sbomChan {
				// check if SBOM is generated from an image
				if sbom.GetImage() != nil {
					// safe SBOM information
					s.IDToSBOMURl.Set(sbom.GetImage().GetDigest(), sbom.GetUrl())

					logrus.WithFields(logrus.Fields{
						"type": "sbom",
						"key":  sbom.GetImage().GetDigest(),
						"url":  sbom.GetUrl(),
					}).Tracef("message received")
				}

				// check if SBOM is generated from a host
				if sbom.GetHost() != nil {
					// safe SBOM information
					s.IDToSBOMURl.Set(sbom.GetHost().GetHostname(), sbom.GetUrl())

					logrus.WithFields(logrus.Fields{
						"type": "sbomhost",
						"key":  sbom.GetHost().GetHostname(),
						"url":  sbom.GetUrl(),
					}).Tracef("message received")
				}
			}
		}()
	}

	return nil
}

func (s server) startTracing(ctx context.Context) error {
	logger := logrus.WithField("type", "connection")

	// generate traces in time intervals
	go func() {
		s.tracing(ctx)
	}()

	// receive flow messages in parallel
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

//nolint:funlen // log statements
func (s server) receiveConnectionMessage(ctx context.Context, connection *cisinapi.Connection) error {
	logger := logrus.WithField("type", "connection")
	src := connection.GetSource()
	dest := connection.GetDestination()
	now := time.Now()

	logger.WithFields(
		logrus.Fields{
			"connection": fmt.Sprintf("%v", connection),
		}).Trace("message received")

	// receive id for source workload
	srcID, err := s.translateWorkloadID(ctx, src.GetId())
	if err != nil {
		return err
	}

	// receive id for destination workload
	destID, err := s.translateWorkloadID(ctx, dest.GetId())
	if err != nil {
		return err
	}

	// world id is not interesting because we can not generate a SBOM for the world :)
	if srcID == constant.WorldID || destID == constant.WorldID {
		logger.WithFields(
			logrus.Fields{
				"srcID":  srcID,
				"destID": destID,
			}).Tracef("ignore world id")

		return nil
	}

	// ignore flow if workload is excluded by config
	if slices.Contains(s.ExcludeWorkloads, srcID) || slices.Contains(s.ExcludeWorkloads, destID) {
		logger.WithFields(
			logrus.Fields{
				"srcID":  srcID,
				"destID": destID,
			}).Tracef("excluded workload")

		return nil
	}

	// check if there exists already information about the source or the destination
	existingSrc, _ := s.Participants.Get(srcID)
	existingDest, _ := s.Participants.Get(destID)

	// set source results
	s.Participants.Set(srcID, endpoint{
		id:          srcID,
		srcResults:  src.GetResults(),
		destResults: existingSrc.destResults,
		timestamp:   now,
	})

	// set destination results
	s.Participants.Set(destID, endpoint{
		id:          destID,
		srcResults:  existingDest.srcResults,
		destResults: dest.GetResults(),
		timestamp:   now,
	})

	// get neighbourhood of the destination
	destNeighbourhood, _ := s.Neighbourhood.Get(destID)
	if slices.ContainsFunc(destNeighbourhood, func(n neighbour) bool {
		return n.id == srcID
	}) {
		logger.WithFields(
			logrus.Fields{
				"srcID":  srcID,
				"destID": destID,
			}).Tracef("already in destination neighbourhood")

		return nil
	}

	// get neighbourhood of the source
	neighbourhood, _ := s.Neighbourhood.Get(srcID)

	// check if destination is already registered as neighbour of the source - otherwise add as neighbour
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

	logger.WithFields(
		logrus.Fields{
			"srcID":  srcID,
			"destID": destID,
		}).Trace("message processed")

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

	// generate debug map
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

	// find trace roots
	roots := s.findTraceRoots()

	logrus.WithField("roots", roots).Trace("found roots")

	// build trace for every root
	for _, root := range roots {
		s.buildTrace(ctx, root, nil)
	}
}

//nolint:funlen,cyclop
func (s server) buildTrace(ctx context.Context, workloadID string, idsInTrace []string) {
	var span trace.Span

	// add current id to ids in trace
	idsInTrace = append(idsInTrace, workloadID)

	participant, ok := s.Participants.Get(workloadID)
	if !ok {
		return
	}

	attributes := make([]attribute.KeyValue, 0)

	sbomIDs := make([]string, 0)

	// add agent module results - evaluated as destination - to trace
	for moduleName, analyse := range participant.destResults {
		attributes = append(attributes, attribute.KeyValue{
			Key:   attribute.Key(moduleName),
			Value: attribute.StringSliceValue(analyse.GetResults()),
		})

		if moduleName == agentmodule.K8sDigestModuleName {
			sbomIDs = analyse.GetResults()
		}
	}

	// add agent module results - evaluated as source - to trace -> results from destination are overridden, because
	// results evaluated as source are more accurate
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
			sbomIDs = analyse.GetResults()
		}
	}

	_, kind, name, _ := id.ParseID(workloadID)
	if kind == id.ExternalWorkloadKind {
		sbomIDs = []string{name}
	}

	// retrieve SBOM URLs
	sboms := s.getSBOMsFromResults(sbomIDs)
	attributes = append(attributes, attribute.KeyValue{
		Key:   constant.SBOMsTraceTag,
		Value: attribute.StringSliceValue(sboms),
	})

	// start span
	ctx, span = s.TracingRepo.GetProvider().Tracer("cisin").Start(ctx, workloadID, trace.WithAttributes(attributes...))

	defer span.End()

	// if workload is not available in neighbourhood as source stop span and return
	neighbourhood, ok := s.Neighbourhood.Get(workloadID)
	if !ok {
		return
	}

	// if workload is available as source in neighbourhood, analyze every neighbour and add them to the trace
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

	// if workload is a pod, get the "base" resource of the pod
	pod, err := s.K8sRepo.GetPod(ctx, name, namespace)
	if errors.IsNotFound(err) {
		// Based on cilium flow tagging it can happen, that an external workload is falsely labeled as pod. We check here if this is the case.
		logrus.WithField("id", workloadID).Debugf("pod not found - try to load external workload")

		_, extErr := s.K8sRepo.GetExternalWorkload(ctx, name, namespace)
		if extErr != nil {
			return "", fmt.Errorf("get external workload: %w: %w", extErr, err)
		}

		return id.GetExternalWorkloadID(name), nil
	}

	if err != nil {
		return "", fmt.Errorf("could not get pod %s for workload ID %s from namespace %s: %w", name, workloadID, namespace, err)
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

func (s server) findTraceRoots() []string {
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
		sbom, ok := s.IDToSBOMURl.Get(result)
		if !ok {
			logrus.WithFields(
				logrus.Fields{
					"key": result,
				},
			).Warn("no sbom found")

			continue
		}

		logrus.WithFields(
			logrus.Fields{
				"key": result,
				"url": sbom,
			},
		).Tracef("sbom found")

		sboms[i] = sbom
	}

	return sboms
}
