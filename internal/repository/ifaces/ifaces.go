// Package ifacesrepository provides access to host interfaces
package ifacesrepository

// Ifaces is the interface to retrieve network information.
type Ifaces interface {
	// GetIPAddresses from host
	GetIPAddresses() ([]string, error)
	// LookupAddr name of an IP address
	LookupAddr(ip string) (string, error)
}
