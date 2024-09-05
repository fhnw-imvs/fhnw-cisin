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

package server

import (
	"reflect"
	"sort"
	"testing"

	"github.com/fhnw-imvs/fhnw-cisin/internal/safemap"
)

func Test_server_findRoots(t *testing.T) {
	tests := []struct {
		name          string
		neighbourhood map[string][]neighbour
		want          []string
	}{
		{
			name: "root",
			neighbourhood: map[string][]neighbour{

				"application/Deployment/application": {
					{id: "application/Deployment/application-child"},
				},
				"cisin/Deployment/cisin-harbor-core": {
					{id: "cisin/StatefulSet/cisin-harbor-redis"},
					{id: "cisin/StatefulSet/cisin-harbor-trivy"},
					{id: "cisin/StatefulSet/cisin-harbor-database"},
					{id: "cisin/Deployment/cisin-harbor-registry"},
					{id: "cisin/Deployment/cisin-harbor-portal"},
					{id: "cisin/Deployment/cisin-harbor-jobservice"},
				},
				"cisin/Deployment/cisin-harbor-jobservice": {
					{id: "cisin/StatefulSet/cisin-harbor-redis"},
					{id: "cisin/StatefulSet/cisin-harbor-database"},
				},
				"cisin/Deployment/cisin-harbor-nginx": {
					{id: "cisin/Deployment/cisin-harbor-core"},
					{id: "cisin/Deployment/cisin-harbor-portal"},
				},
				"cisin/Deployment/cisin-harbor-registry": {
					{id: "cisin/StatefulSet/cisin-harbor-redis"},
				},
				"cisin/StatefulSet/cisin-harbor-trivy": {
					{id: "cisin/StatefulSet/cisin-harbor-redis"},
				},
				"external/Workload/external": {
					{id: "application/Deployment/application"},
					{id: "cisin/Deployment/cisin-harbor-nginx0"},
				},
			},
			want: []string{
				"cisin/Deployment/cisin-harbor-nginx",
				"external/Workload/external",
			},
		},
		{
			name: "circle",
			neighbourhood: map[string][]neighbour{
				"1": {
					{
						id: "2",
					},
				},
				"2": {
					{
						id: "1",
					},
				},
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := server{
				Neighbourhood: safemap.NewSafeMap[string, []neighbour](),
			}

			for key, value := range tt.neighbourhood {
				s.Neighbourhood.Set(key, value)
			}

			roots := s.findTraceRoots()

			sort.Strings(roots)

			if got := roots; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findTraceRoots() = %v, want %v", got, tt.want)
			}
		})
	}
}
