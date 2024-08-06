// Package apirepository provides access to APIs
package apirepository

// API is the interface to access an api.
type API interface {
	// Get returns data from given path
	Get(p string) ([]byte, error)
}
