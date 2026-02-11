package fallback

import (
	"context"
	"os"
	"sync"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type Store struct {
	rdb *redis.Client

	mu  sync.RWMutex
	mem map[string][]byte
}

func New(addr, password string, db int) *Store {
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	return &Store{
		rdb: redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: password,
			DB:       db,
		}),
		mem: map[string][]byte{},
	}
}

func (s *Store) GetHTML(key string) ([]byte, error) {
	if s == nil || key == "" {
		return nil, nil
	}

	s.mu.RLock()
	if s.mem != nil {
		if v, ok := s.mem[key]; ok && len(v) > 0 {
			out := make([]byte, len(v))
			copy(out, v)
			s.mu.RUnlock()
			return out, nil
		}
	}
	s.mu.RUnlock()

	if s.rdb == nil {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	b, err := s.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.mem == nil {
		s.mem = map[string][]byte{}
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	s.mem[key] = cp
	s.mu.Unlock()

	return b, nil
}

func (s *Store) SetHTML(key string, html []byte) error {
	if s == nil || key == "" || len(html) == 0 {
		return nil
	}

	s.mu.Lock()
	if s.mem == nil {
		s.mem = map[string][]byte{}
	}
	cp := make([]byte, len(html))
	copy(cp, html)
	s.mem[key] = cp
	s.mu.Unlock()

	if s.rdb == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.rdb.Set(ctx, key, html, 0).Err()
}

func (s *Store) RefreshFromFile(key, path string) {
	if s == nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	_ = s.SetHTML(key, data)
}

func (s *Store) StartFileRefresher(key, path string, every time.Duration) {
	if s == nil || every <= 0 {
		return
	}
	s.RefreshFromFile(key, path)

	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			s.RefreshFromFile(key, path)
		}
	}()
}