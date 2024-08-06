package apirepository

import (
	"fmt"
	"io"
	"net/http"

	"gitlab.fhnw.ch/cloud/mse-cloud/cisin/internal/constant"
)

type apiHTTP struct {
	address string
}

// NewAPI creates a http based implementation of API.
func NewAPI(address string) API {
	return &apiHTTP{
		address: address,
	}
}

func (a apiHTTP) Get(p string) ([]byte, error) {
	resp, err := http.Get(fmt.Sprintf("%s%s", a.address, p))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", p, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status code %d: %w", resp.StatusCode, constant.ErrUnknown)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return data, nil
}
