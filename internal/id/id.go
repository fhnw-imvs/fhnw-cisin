package id

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/sirupsen/logrus"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	ifacesrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifaces"
)

const numberOfIDElements = 3

// HostKind fake k8s type for a host.
const HostKind = "Host"

// HostNamespace fake k8s namespace for a host.
const HostNamespace = "host"

const (
	ExternalWorkloadKind      = "Workload"
	ExternalWorkloadNamespace = "external"
)

func GetK8sID(endpoint *flow.Endpoint) (string, error) {
	workloads := endpoint.GetWorkloads()
	if len(workloads) > 0 {
		return getKubernetesWorkloadID(endpoint.GetNamespace(), workloads[0].GetKind(), workloads[0].GetName()), nil
	}

	logrus.WithField("endpoint", endpoint).Debug("no workload")

	if len(endpoint.GetPodName()) > 0 {
		return getKubernetesWorkloadID(endpoint.GetNamespace(), "Pod", endpoint.GetPodName()), nil
	}

	return "", fmt.Errorf("could not evaluate k8s id: %w", constant.ErrNotFound)
}

func ParseID(id string) (namespace, kind, name string, err error) {
	split := strings.Split(id, "/")
	if len(split) != numberOfIDElements {
		return "", "", "", fmt.Errorf("id %s is invalid: %w", id, constant.ErrInvalid)
	}

	return split[0], split[1], split[2], nil
}

func getKubernetesWorkloadID(namespace, kind, name string) string {
	return fmt.Sprintf("%s/%s/%s", namespace, kind, name)
}

func GetVMID(ip string, nodeName string, ifaces ifacesrepository.Ifaces) (string, error) {
	ipAdresses, err := ifaces.GetIPAddresses()
	if err != nil {
		return "", fmt.Errorf("could not get host ip addresses: %w", err)
	}

	if slices.Contains(ipAdresses, ip) {
		return fmt.Sprintf("%s/%s/%s", ExternalWorkloadNamespace, ExternalWorkloadKind, nodeName), nil
	}

	name, err := ifaces.LookupAddr(ip)
	if err != nil {
		return "", fmt.Errorf("could not get name for ip address %s: %w", ip, err)
	}

	return fmt.Sprintf("%s/%s/%s", HostNamespace, HostKind, name), nil
}

func GetExternalWorkloadID(nodeName string) string {
	return fmt.Sprintf("%s/%s/%s", ExternalWorkloadNamespace, ExternalWorkloadKind, nodeName)
}
