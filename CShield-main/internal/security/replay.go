package security

import (
	"sync"
	"time"
)

type ReplayStore struct {
	mu         sync.Mutex
	m          map[string]map[string]int64
	maxPerSess int
}

func NewReplayStore(maxPerSess int) *ReplayStore {
	if maxPerSess <= 0 {
		maxPerSess = 64
	}
	return &ReplayStore{m: map[string]map[string]int64{}, maxPerSess: maxPerSess}
}

func (s *ReplayStore) Mark(sessID, nonce string, exp int64) bool {
	if sessID == "" || nonce == "" {
		return false
	}
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	set, ok := s.m[sessID]
	if !ok {
		set = map[string]int64{}
		s.m[sessID] = set
	}
	for n, e := range set {
		if e <= now {
			delete(set, n)
		}
	}
	if _, exists := set[nonce]; exists {
		return false
	}
	if len(set) >= s.maxPerSess {
		var oldest string
		var oldestExp int64 = 1 << 62
		for n, e := range set {
			if e < oldestExp {
				oldest = n
				oldestExp = e
			}
		}
		if oldest != "" {
			delete(set, oldest)
		}
	}
	set[nonce] = exp
	return true
}

func (s *ReplayStore) Reset(sessID string) {
	s.mu.Lock()
	delete(s.m, sessID)
	s.mu.Unlock()
}