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
