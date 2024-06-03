package apirepository

type API interface {
	Get(p string) ([]byte, error)
}
