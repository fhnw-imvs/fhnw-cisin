// Copyright (c) 2024 Esra Siegert
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
