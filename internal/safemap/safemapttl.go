package safemap

import (
	"context"
	"sync"
	"time"

	"golang.org/x/exp/maps"
)

type safeMapTTL[T comparable, U any] struct {
	safeMap     map[T]U
	mux         sync.Mutex
	ttl         time.Duration
	ttlMap      map[T]time.Time
	ttlInterval time.Duration
}

func NewSafeMapTTL[T comparable, U any](ctx context.Context, ttlInterval, ttl time.Duration) SafeMap[T, U] {
	s := &safeMapTTL[T, U]{
		safeMap:     map[T]U{},
		mux:         sync.Mutex{},
		ttlMap:      map[T]time.Time{},
		ttl:         ttl,
		ttlInterval: ttlInterval,
	}

	go func() {
		ticker := time.NewTicker(ttlInterval)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.ttlCheck()
		}
	}()

	return s
}

func (s *safeMapTTL[T, U]) Get(t T) (U, bool) {
	s.mux.Lock()

	defer s.mux.Unlock()

	var u U

	item, ok := s.safeMap[t]
	if !ok {
		return u, false
	}

	return item, true
}

func (s *safeMapTTL[T, U]) Set(t T, u U) {
	s.mux.Lock()

	defer s.mux.Unlock()

	s.safeMap[t] = u
	s.ttlMap[t] = time.Now().Add(s.ttl)
}

func (s *safeMapTTL[T, U]) Keys() []T {
	s.mux.Lock()

	defer s.mux.Unlock()

	return maps.Keys(s.safeMap)
}

func (s *safeMapTTL[T, U]) ttlCheck() {
	s.mux.Lock()

	defer s.mux.Unlock()

	now := time.Now()

	for t := range s.safeMap {
		ttl := s.ttlMap[t]

		if ttl.After(now) {
			continue
		}

		delete(s.safeMap, t)
		delete(s.ttlMap, t)
	}
}
