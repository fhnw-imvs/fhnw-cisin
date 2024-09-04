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
