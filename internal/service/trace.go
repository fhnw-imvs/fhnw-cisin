package service

// TraceService provides traces related services.
type TraceService interface {
	// List lists trace ids
	List() ([]string, error)
	// ListSBOMs lists SBOMs from a trace
	ListSBOMs(traceID string) ([]string, error)
}
