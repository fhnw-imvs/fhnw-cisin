// Package analyze contains subcommand to analyze and list traces.
package analyze

import (
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/analyze/list"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/analyze/sbom"
)

// Analyze contains the subcommands for the analyze command.
type Analyze struct {
	List list.List `cmd:"" help:"List trace ids available"`
	SBOM sbom.SBOM `cmd:"" help:"Find vulnerabilities based on SBOM urls in trace tags"`
}
