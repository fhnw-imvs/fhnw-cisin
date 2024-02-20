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
