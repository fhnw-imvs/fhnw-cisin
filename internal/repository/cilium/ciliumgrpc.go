package ciliumrepository

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
)

type ciliumHTTP struct {
	client *client.Client
}

func NewHTTP(address string) (Cilium, error) {
	ciliumClient, err := client.NewClient(address)
	if err != nil {
		return nil, fmt.Errorf("create cilium client: %w", err)
	}

	return ciliumHTTP{
		client: ciliumClient,
	}, nil
}

func (c ciliumHTTP) GetIdentity(id string) (*models.Endpoint, error) {
	endpoint, err := c.client.EndpointGet(id)
	if err != nil {
		return nil, fmt.Errorf("get endpoint: %w", err)
	}

	return endpoint, nil
}

func (c ciliumHTTP) ListIdentities() ([]*models.Endpoint, error) {
	endpointList, err := c.client.EndpointList()
	if err != nil {
		return nil, fmt.Errorf("list endpotint: %w", err)
	}

	return endpointList, nil
}
