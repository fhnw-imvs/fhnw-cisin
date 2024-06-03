package server

import (
	"reflect"
	"testing"

	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/safemap"
)

func Test_server_findRoots(t *testing.T) {
	type fields struct {
		neighbourhood safemap.SafeMap[string, []neighbour]
	}

	tests := []struct {
		name          string
		neighbourhood map[string][]neighbour
		fields        fields
		want          []string
	}{
		{
			name: "root",
			neighbourhood: map[string][]neighbour{
				"1": {
					{
						id: "2",
					},
				},
				"2": nil,
			},
			fields: fields{
				neighbourhood: safemap.NewSafeMap[string, []neighbour](),
			},
			want: []string{
				"1",
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
			fields: fields{
				neighbourhood: safemap.NewSafeMap[string, []neighbour](),
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := server{
				Neighbourhood: tt.fields.neighbourhood,
			}

			for key, value := range tt.neighbourhood {
				s.Neighbourhood.Set(key, value)
			}

			if got := s.findRoots(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findRoots() = %v, want %v", got, tt.want)
			}
		})
	}
}
