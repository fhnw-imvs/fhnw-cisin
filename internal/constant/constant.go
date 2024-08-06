// Package constant contains constant values used across CISIN
package constant

import "errors"

// predefined errors.
var (
	ErrNotFound = errors.New("not found")
	ErrUnknown  = errors.New("unknown")
	ErrInvalid  = errors.New("invalid")
)

const (
	// WorldID is the ID for everything outside the Cilium cluster mesh.
	WorldID = "world/world/world"
	// SBOMMediaType is the format of the SBOM.
	SBOMMediaType = "application/vnd.spdx+json"
	// SBOMsTraceTag is tag used for the SBOM URLs in a trace.
	SBOMsTraceTag = "sboms"
)

// supported node types.
const (
	K8sNodeType = "k8s"
	HostType    = "host"
)

// EphemeralPortStart first ephemeral port.
const EphemeralPortStart = 32768
