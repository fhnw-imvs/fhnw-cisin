package constant

import "errors"

var (
	ErrNotFound = errors.New("not found")
	ErrUnknown  = errors.New("unknown")
	ErrInvalid  = errors.New("invalid")
)

const (
	WorldID       = "world/world/world"
	SBOMMediaType = "application/vnd.cyclonedx+json"
	SBOMsTraceTag = "sboms"
)

const (
	K8sNodeType = "k8s"
	VMNodeType  = "vm"
)

const EphemeralPortStart = 32768
