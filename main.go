// CISIN listen to the Cilium Hubble socket to retrieve network traffic from your Cilium cluster mesh. It not only supports
// Kubernetes cluster, but also hosts included as external workload into your Cilium cluster mesh. Based on the network
// traffic it generates traces enriched with SBOM information about the network participants.
package main

import (
	"github.com/alecthomas/kong"
	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/cmd"
)

//go:generate go run github.com/bufbuild/buf/cmd/buf generate

func main() {
	ctx := kong.Parse(&cmd.CLI{})
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
