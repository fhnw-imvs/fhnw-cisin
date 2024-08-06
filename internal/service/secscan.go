package service

// SecScanService provides security scan related services.
type SecScanService interface {
	// Scan SBOMs for vulnerabilities
	Scan(sbomURLs []string) error
}
