package analyze

import (
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/analyze/list"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd/analyze/sbom"
)

type Analyze struct {
	List list.List `cmd:""`
	SBOM sbom.SBOM `cmd:""`
}
