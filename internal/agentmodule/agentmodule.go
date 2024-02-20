package agentmodule

import (
	"github.com/cilium/cilium/api/v1/flow"
	cisinapi "gitlab.fhnw.ch/cloud/mse-cloud/cisin/gen/go/proto"
)

type AgentModule interface {
	Analyze(ip string, port int, e *flow.Endpoint) (*cisinapi.Analyse, error)
	Compatibility() []cisinapi.WorkloadType
	ModuleName() string
}
