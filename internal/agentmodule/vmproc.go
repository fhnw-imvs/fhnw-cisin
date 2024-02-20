package agentmodule

import (
	"github.com/cilium/cilium/api/v1/flow"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/ifacesrepository"
	procrepository "gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/repository/proc"
	"slices"
	"strconv"
)

const VMProcModuleName = "vm_proc"

type vmProcModule struct {
	proc   procrepository.Proc
	ifaces ifacesrepository.Ifaces
}

func NewVMProcModule(procRepo procrepository.Proc, ifacesRepo ifacesrepository.Ifaces) (AgentModule, error) {
	return vmProcModule{
		proc:   procRepo,
		ifaces: ifacesRepo,
	}, nil
}

func (v vmProcModule) Analyze(ip string, port int, e *flow.Endpoint) (*cisinapi.Analyse, error) {
	ipAddresses, err := v.ifaces.GetIPAddresses()
	if err != nil {
		return nil, err
	}

	if slices.Contains(ipAddresses, ip) {
		pid, err := v.proc.GetPIDFromPort(port)
		if err != nil {
			return nil, err
		}

		return &cisinapi.Analyse{
			Results: []string{
				strconv.Itoa(pid),
			},
		}, nil
	}

	return nil, err
}

func (v vmProcModule) Compatibility() []cisinapi.WorkloadType {
	return []cisinapi.WorkloadType{
		cisinapi.WorkloadType_JAVA,
		cisinapi.WorkloadType_DOCKER,
	}
}

func (v vmProcModule) ModuleName() string {
	return VMProcModuleName
}
