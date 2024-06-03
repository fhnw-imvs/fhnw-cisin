package service

type TraceService interface {
	List() ([]string, error)
	ListSBOMs(traceID string) ([]string, error)
}
