package agent

import (
	"context"
)

type Agent interface {
	Start(ctx context.Context) error
}
