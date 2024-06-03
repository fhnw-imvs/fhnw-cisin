package service

type SecScanService interface {
	Scan(sbomURLs []string) error
}
