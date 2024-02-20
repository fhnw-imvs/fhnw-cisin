package ciliumrepository

import (
	"github.com/cilium/cilium/api/v1/models"
)

type Cilium interface {
	GetIdentity(id string) (*models.Endpoint, error)
	ListIdentities() ([]*models.Endpoint, error)
}
