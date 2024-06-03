package cmd

import (
	agentcmd "gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/agent"
	analyzecmd "gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/analyze"
	servercmd "gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/server"
)

type CLI struct {
	Agent   agentcmd.Agent     `cmd:""`
	Server  servercmd.Server   `cmd:""`
	Analyze analyzecmd.Analyze `cmd:""`
}
