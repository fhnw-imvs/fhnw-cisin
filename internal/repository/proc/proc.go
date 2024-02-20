package procrepository

type Proc interface {
	GetPIDFromPort(port int) (int, error)
}
