package ifacesrepository

type Ifaces interface {
	GetIPAddresses() ([]string, error)
	LookupAddr(ip string) (string, error)
}
