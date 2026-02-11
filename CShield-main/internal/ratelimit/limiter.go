package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	last     time.Time
	capacity float64
	rate     float64
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
	window  time.Duration
}

func New(globalRPS, burst int, windowMs int) *Limiter {
	if globalRPS <= 0 {
		globalRPS = 100
	}
	if burst <= 0 {
		burst = globalRPS
	}
	if windowMs <= 0 {
		windowMs = 1000
	}
	return &Limiter{
		buckets: map[string]*bucket{},
		rate:    float64(globalRPS),
		burst:   float64(burst),
		window:  time.Duration(windowMs) * time.Millisecond,
	}
}

func (l *Limiter) allow(key string, now time.Time) bool {
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now, capacity: l.burst, rate: l.rate}
		l.buckets[key] = b
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allow(key, time.Now())
}