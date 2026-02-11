package analytics

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

type Snap struct {
	Requests    uint64            `json:"requests"`
	Proxied     uint64            `json:"proxied"`
	Blocked     uint64            `json:"blocked"`
	Captcha     uint64            `json:"captcha"`
	Dropped     uint64            `json:"dropped"`
	Throttled   uint64            `json:"throttled"`
	Errors      uint64            `json:"errors"`
	BytesIn     uint64            `json:"bytes_in"`
	BytesOut    uint64            `json:"bytes_out"`
	ByStatus    map[int]uint64    `json:"by_status"`
	UpdatedAt   int64             `json:"updated_at"`
	ExtraGauges map[string]uint64 `json:"extra_gauges"`
}

type IPStats struct {
	Requests uint64 `json:"requests"`
	Attacks  uint64 `json:"attacks"`
	First    int64  `json:"first_seen"`
	Last     int64  `json:"last_seen"`
}

type AttackEvent struct {
	Time   int64  `json:"time"`
	IP     string `json:"ip"`
	Path   string `json:"path"`
	Method string `json:"method"`
	UA     string `json:"ua"`
	Reason string `json:"reason"`
	Action string `json:"action"`
	Score  int    `json:"score"`
	Status int    `json:"status"`
}

type Metrics struct {
	requests  atomic.Uint64
	proxied   atomic.Uint64
	blocked   atomic.Uint64
	captcha   atomic.Uint64
	dropped   atomic.Uint64
	throttled atomic.Uint64
	errors    atomic.Uint64
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64

	mu       sync.Mutex
	byStatus map[int]uint64
	gauges   map[string]*atomic.Uint64

	ipMu sync.Mutex
	ips  map[string]*IPStats

	attackMu   sync.Mutex
	attacks    []AttackEvent
	attackHead int
}

const attackBufferSize = 512

func New() *Metrics {
	return &Metrics{
		byStatus: map[int]uint64{},
		gauges:   map[string]*atomic.Uint64{},
		ips:      map[string]*IPStats{},
		attacks:  make([]AttackEvent, 0, attackBufferSize),
	}
}

func (m *Metrics) IncRequests()      { m.requests.Add(1) }
func (m *Metrics) IncProxied()       { m.proxied.Add(1) }
func (m *Metrics) IncBlocked()       { m.blocked.Add(1) }
func (m *Metrics) IncCaptcha()       { m.captcha.Add(1) }
func (m *Metrics) IncDropped()       { m.dropped.Add(1) }
func (m *Metrics) IncThrottled()     { m.throttled.Add(1) }
func (m *Metrics) IncErrors()        { m.errors.Add(1) }
func (m *Metrics) AddBytesIn(n int)  { if n > 0 { m.bytesIn.Add(uint64(n)) } }
func (m *Metrics) AddBytesOut(n int) { if n > 0 { m.bytesOut.Add(uint64(n)) } }

func (m *Metrics) IncStatus(code int) {
	m.mu.Lock()
	m.byStatus[code]++
	m.mu.Unlock()
}

func (m *Metrics) Gauge(name string) *atomic.Uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gauges[name]
	if !ok {
		g = &atomic.Uint64{}
		m.gauges[name] = g
	}
	return g
}

func (m *Metrics) RecordIP(ip string) {
	if ip == "" {
		return
	}
	now := time.Now().Unix()
	m.ipMu.Lock()
	s, ok := m.ips[ip]
	if !ok {
		s = &IPStats{First: now}
		m.ips[ip] = s
	}
	s.Requests++
	s.Last = now
	m.ipMu.Unlock()
}

func (m *Metrics) MarkAttack(ip string) {
	if ip == "" {
		return
	}
	now := time.Now().Unix()
	m.ipMu.Lock()
	s, ok := m.ips[ip]
	if !ok {
		s = &IPStats{First: now}
		m.ips[ip] = s
	}
	s.Attacks++
	s.Last = now
	m.ipMu.Unlock()
}

func (m *Metrics) IPStatsSnapshot() map[string]IPStats {
	out := map[string]IPStats{}
	m.ipMu.Lock()
	for ip, s := range m.ips {
		out[ip] = IPStats{
			Requests: s.Requests,
			Attacks:  s.Attacks,
			First:    s.First,
			Last:     s.Last,
		}
	}
	m.ipMu.Unlock()
	return out
}

func (m *Metrics) AddAttack(e AttackEvent) {
	m.attackMu.Lock()
	if len(m.attacks) < attackBufferSize {
		m.attacks = append(m.attacks, e)
	} else {
		i := m.attackHead % attackBufferSize
		if i < 0 {
			i = 0
		}
		m.attacks[i] = e
		m.attackHead = (m.attackHead + 1) % attackBufferSize
	}
	m.attackMu.Unlock()
}

func (m *Metrics) AttackSnapshot() []AttackEvent {
	m.attackMu.Lock()
	n := len(m.attacks)
	if n == 0 {
		m.attackMu.Unlock()
		return nil
	}
	out := make([]AttackEvent, 0, n)
	if n < attackBufferSize || m.attackHead == 0 {
		out = append(out, m.attacks[:n]...)
	} else {
		for i := 0; i < n; i++ {
			idx := (m.attackHead + i) % n
			out = append(out, m.attacks[idx])
		}
	}
	m.attackMu.Unlock()
	return out
}

func (m *Metrics) Snapshot() Snap {
	m.mu.Lock()
	cp := make(map[int]uint64, len(m.byStatus))
	for k, v := range m.byStatus {
		cp[k] = v
	}
	eg := map[string]uint64{}
	for k, g := range m.gauges {
		eg[k] = g.Load()
	}
	m.mu.Unlock()

	return Snap{
		Requests:    m.requests.Load(),
		Proxied:     m.proxied.Load(),
		Blocked:     m.blocked.Load(),
		Captcha:     m.captcha.Load(),
		Dropped:     m.dropped.Load(),
		Throttled:   m.throttled.Load(),
		Errors:      m.errors.Load(),
		BytesIn:     m.bytesIn.Load(),
		BytesOut:    m.bytesOut.Load(),
		ByStatus:    cp,
		UpdatedAt:   time.Now().Unix(),
		ExtraGauges: eg,
	}
}

func (m *Metrics) SnapshotJSON() []byte {
	b, _ := json.Marshal(m.Snapshot())
	return b
}