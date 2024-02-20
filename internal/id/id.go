package id

import (
	"fmt"
	"github.com/cilium/cilium/api/v1/flow"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifacesrepository"
)

func GetK8sID(e *flow.Endpoint) (string, error) {
	workloads := e.GetWorkloads()

	if len(workloads) == 0 {
		return "", constant.ErrNotFound
	}

	return getKubernetesWorkloadID(workloads[0]), nil
}

func getKubernetesWorkloadID(w *flow.Workload) string {
	return fmt.Sprintf("%s/%s", w.GetKind(), w.GetName())
}

func GetVmID(ip string, ifaces ifacesrepository.Ifaces) (string, error) {
	name, err := ifaces.LookupAddr(ip)
	if err != nil {
		return "", err
	}

	return name, nil
}
