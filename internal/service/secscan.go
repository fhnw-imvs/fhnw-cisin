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

package service

// SecScanService provides security scan related services.
type SecScanService interface {
	// ScanStdout SBOMs for vulnerabilities
	ScanStdout(sbomURLs []string) error
	Scan(sbomPath string) (*SecScanResult, error)
}

type SecScanResult struct {
	Matches []SecScanMatch `json:"matches"`
}

type SecScanMatch struct {
	Vulnerability SecScanVulnerability `json:"vulnerability"`
}

type SecScanVulnerability struct {
	ID                     string                 `json:"id"`
	Severity               string                 `json:"severity"`
	RelatedVulnerabilities []SecScanVulnerability `json:"relatedVulnerabilities"`
	CVSs                   []SecScanCVS           `json:"cvss,omitempty"`
}

type SecScanCVS struct {
	Metrics SecScanCVSMetrics `json:"metrics"`
}

type SecScanCVSMetrics struct {
	BaseScore float64 `json:"baseScore"`
}
