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

// Package list contains the list command. The list command lists trace ids from a Jaeger instance.
package list

import (
	"fmt"
	"time"

	apirepository "github.com/fhnw-imvs/fhnw-cisin/internal/repository/api"
	traceservice "github.com/fhnw-imvs/fhnw-cisin/internal/service/trace"
)

// List is the command to list trace ids from Jaeger.
type List struct {
	Jaeger       string        `default:"http://localhost:14268" help:"Jaeger address"`
	ServiceName  string        `default:"cisin"                  help:"Service name"`
	HistoryLimit time.Duration `default:"1h"                     help:"History limit"`
}

// Run executes the command.
func (l List) Run() error {
	apiRepo := apirepository.NewAPI(l.Jaeger)

	traceService := traceservice.New(apiRepo, l.ServiceName, l.HistoryLimit)

	traceIDs, err := traceService.ListIDs()
	if err != nil {
		return fmt.Errorf("listing traces: %w", err)
	}

	for _, traceID := range traceIDs {
		fmt.Println(traceID)
	}

	return nil
}
