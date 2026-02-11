package cache

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type Entry struct {
	Key         string
	Status      int
	Body        []byte
	Headers     map[string]string
	IP          string
	Path        string
	Method      string
	Fingerprint string
	CreatedAt   int64
	ExpiresAt   int64
}

type Store struct {
	mu       sync.RWMutex
	items    map[string]*Entry
	maxItems int
	ttl      time.Duration
	rdb      *redis.Client
	prefix   string
}

func New(maxItems int, ttl time.Duration) *Store {
	if maxItems <= 0 {
		maxItems = 1024
	}
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &Store{
		items:    map[string]*Entry{},
		maxItems: maxItems,
		ttl:      ttl,
	}
}

func NewWithRedis(redisAddr, redisPassword string, redisDB int, maxItems int, ttl time.Duration) *Store {
	if maxItems <= 0 {
		maxItems = 1024
	}
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	if redisAddr == "" {
		return New(maxItems, ttl)
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})
	return &Store{
		items:    map[string]*Entry{},
		maxItems: maxItems,
		ttl:      ttl,
		rdb:      rdb,
		prefix:   "edgecache:",
	}
}

func (s *Store) now() int64 {
	return time.Now().Unix()
}

func (s *Store) key(ip, path, method, fingerprint string, perIP bool) string {
	if perIP {
		return ip + "|" + method + "|" + path + "|" + fingerprint
	}
	return method + "|" + path + "|" + fingerprint
}

func (s *Store) Get(ip, path, method, fingerprint string, perIP bool) (*Entry, bool) {
	k := s.key(ip, path, method, fingerprint, perIP)
	s.mu.RLock()
	ent, ok := s.items[k]
	s.mu.RUnlock()
	if ok {
		now := s.now()
		if ent.ExpiresAt > 0 && ent.ExpiresAt <= now {
			s.mu.Lock()
			if cur, ok2 := s.items[k]; ok2 && cur == ent {
				delete(s.items, k)
			}
			s.mu.Unlock()
			return nil, false
		}
		return ent, true
	}
	if s.rdb == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := s.rdb.Get(ctx, s.prefix+k).Bytes()
	if err != nil {
		return nil, false
	}
	var loaded Entry
	if json.Unmarshal(data, &loaded) != nil {
		return nil, false
	}
	now := s.now()
	if loaded.ExpiresAt > 0 && loaded.ExpiresAt <= now {
		_ = s.rdb.Del(ctx, s.prefix+k).Err()
		return nil, false
	}
	s.mu.Lock()
	if len(s.items) >= s.maxItems {
		s.evictLocked(now)
	}
	cp := loaded
	s.items[k] = &cp
	s.mu.Unlock()
	return &cp, true
}

func (s *Store) Set(ip, path, method, fingerprint string, perIP bool, status int, body []byte, headers map[string]string) {
	k := s.key(ip, path, method, fingerprint, perIP)
	now := s.now()
	exp := now + int64(s.ttl.Seconds())
	ent := &Entry{
		Key:         k,
		Status:      status,
		Body:        append([]byte(nil), body...),
		Headers:     map[string]string{},
		IP:          ip,
		Path:        path,
		Method:      method,
		Fingerprint: fingerprint,
		CreatedAt:   now,
		ExpiresAt:   exp,
	}
	for hk, hv := range headers {
		ent.Headers[hk] = hv
	}

	s.mu.Lock()
	if len(s.items) >= s.maxItems {
		s.evictLocked(now)
	}
	s.items[k] = ent
	s.mu.Unlock()
	if s.rdb != nil {
		data, err := json.Marshal(ent)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = s.rdb.Set(ctx, s.prefix+k, data, s.ttl).Err()
			cancel()
		}
	}
}

func (s *Store) evictLocked(now int64) {
	for k, v := range s.items {
		if v.ExpiresAt > 0 && v.ExpiresAt <= now {
			delete(s.items, k)
		}
	}
	if len(s.items) <= s.maxItems {
		return
	}
	n := len(s.items) - s.maxItems
	for k := range s.items {
		delete(s.items, k)
		n--
		if n <= 0 {
			break
		}
	}
}

func (s *Store) PurgeExpired() {
	now := s.now()
	s.mu.Lock()
	for k, v := range s.items {
		if v.ExpiresAt > 0 && v.ExpiresAt <= now {
			delete(s.items, k)
		}
	}
	s.mu.Unlock()
}