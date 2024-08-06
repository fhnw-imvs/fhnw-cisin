// Package safemap provides a generic, thread safe map
package safemap

import (
	"golang.org/x/sync/syncmap"
)

// SafeMap is an interface for a generic, thread safe map.
type SafeMap[T, U any] interface {
	// Get returns a value
	Get(t T) (U, bool)
	// Set sets a value
	Set(t T, u U)
	// Keys lists all available keys
	Keys() []T
}

type safeMap[T, U any] struct {
	safeMap syncmap.Map
}

// NewSafeMap returns an implementation of SafeMap.
func NewSafeMap[T, U any]() SafeMap[T, U] {
	return &safeMap[T, U]{
		safeMap: syncmap.Map{},
	}
}

func (s *safeMap[T, U]) Get(t T) (U, bool) {
	var u U

	item, ok := s.safeMap.Load(t)
	if !ok {
		return u, false
	}

	if _, ok := item.(U); !ok {
		return u, false
	}

	return item.(U), true
}

func (s *safeMap[T, U]) Set(t T, u U) {
	s.safeMap.Store(t, u)
}

func (s *safeMap[T, U]) Keys() []T {
	keys := make([]T, 0)

	s.safeMap.Range(func(key, _ any) bool {
		keys = append(keys, key.(T))

		return true
	})

	return keys
}
