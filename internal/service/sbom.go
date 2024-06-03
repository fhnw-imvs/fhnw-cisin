package service

import "context"

type SBOMService interface {
	GenerateSBOM(ctx context.Context, location string) (string, error)
}
