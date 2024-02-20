package ciliumrepository

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
)

type ciliumHTTP struct {
	client *client.Client
}

func NewHTTP(address string) (Cilium, error) {
	c, err := client.NewClient(address)
	if err != nil {
		return nil, err
	}

	return ciliumHTTP{
		client: c,
	}, nil
}

func (c ciliumHTTP) GetIdentity(id string) (*models.Endpoint, error) {
	return c.client.EndpointGet(id)
}

func (c ciliumHTTP) ListIdentities() ([]*models.Endpoint, error) {
	return c.client.EndpointList()
}
