// Package cmd contains commands base structure
package cmd

import (
	agentcmd "gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/agent"
	analyzecmd "gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/analyze"
	servercmd "gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/server"
)

// CLI contains the base commands for CISIN.
type CLI struct {
	Agent   agentcmd.Agent     `cmd:"" help:"Start CISIN agent"`
	Server  servercmd.Server   `cmd:"" help:"Start CISIN server"`
	Analyze analyzecmd.Analyze `cmd:"" help:"Analyse traces "`
}
