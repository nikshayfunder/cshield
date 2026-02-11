package peer

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

type Node struct {
	ID   string `json:"id"`
	Host string `json:"host"`
}

type Config struct {
	SmartRouting   bool   `json:"smart_routing"`
	MultiScrubbing bool   `json:"multi_scrubbing"`
	Peers          []Node `json:"peers"`
}

type nodeHealth struct {
	Node       Node
	Latency    time.Duration
	Healthy    bool
	Failures   int
	LastUsed   time.Time
	LastUpdate time.Time
	Region     string
}

type Service struct {
	smartRouting   bool
	multiScrubbing bool

	client fasthttp.Client

	httpClient *http.Client

	mu       sync.RWMutex
	nodes    []*nodeHealth
	ipRegion map[string]string
}

type scrubRequest struct {
	IP        string            `json:"ip"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Cookies   []string          `json:"cookies"`
	UA        string            `json:"ua"`
	BodyBytes int               `json:"body_bytes"`
}

type scrubResponse struct {
	Allow bool `json:"allow"`
}

type NodeStats struct {
	ID        string `json:"id"`
	Host      string `json:"host"`
	Healthy   bool   `json:"healthy"`
	LatencyMs int64  `json:"latency_ms"`
	Failures  int    `json:"failures"`
}

func NewService(cfg Config) *Service {
	s := &Service{
		smartRouting:   cfg.SmartRouting,
		multiScrubbing: cfg.MultiScrubbing,
		client: fasthttp.Client{
			ReadTimeout:     3 * time.Second,
			WriteTimeout:    3 * time.Second,
			MaxConnsPerHost: 256,
		},
		httpClient: &http.Client{Timeout: 1500 * time.Millisecond},
		ipRegion:   map[string]string{},
	}
	for _, n := range cfg.Peers {
		host := strings.TrimRight(n.Host, "/")
		if host == "" {
			continue
		}
		nn := n
		nn.Host = host
		ip := hostIP(host)
		region := s.regionForIP(ip)
		s.nodes = append(s.nodes, &nodeHealth{
			Node:    nn,
			Healthy: true,
			Region:  region,
		})
	}
	return s
}

func (s *Service) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes) > 0
}

func (s *Service) Stats() []NodeStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]NodeStats, 0, len(s.nodes))
	for _, n := range s.nodes {
		lat := int64(n.Latency / time.Millisecond)
		out = append(out, NodeStats{
			ID:        n.Node.ID,
			Host:      n.Node.Host,
			Healthy:   n.Healthy,
			LatencyMs: lat,
			Failures:  n.Failures,
		})
	}
	return out
}

func (s *Service) pickOrder(clientRegion string) []*nodeHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.nodes) == 0 {
		return nil
	}
	out := make([]*nodeHealth, len(s.nodes))
	copy(out, s.nodes)
	if !s.smartRouting || len(out) == 1 {
		return out
	}
	sort.Slice(out, func(i, j int) bool {
		a := out[i]
		b := out[j]
		sameA := clientRegion != "" && a.Region != "" && a.Region == clientRegion
		sameB := clientRegion != "" && b.Region != "" && b.Region == clientRegion
		if sameA != sameB {
			return sameA
		}
		if a.Healthy != b.Healthy {
			return a.Healthy && !b.Healthy
		}
		if a.Failures != b.Failures {
			return a.Failures < b.Failures
		}
		if a.Latency != b.Latency {
			return a.Latency < b.Latency
		}
		return a.Node.ID < b.Node.ID
	})
	return out
}

func (s *Service) updateHealth(n *nodeHealth, ok bool, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n.LastUpdate = time.Now()
	if ok {
		n.Healthy = true
		n.Latency = latency
		if n.Failures > 0 {
			n.Failures--
		}
		n.LastUsed = n.LastUpdate
		return
	}
	n.Failures++
	if n.Failures > 3 {
		n.Healthy = false
	}
	n.LastUsed = n.LastUpdate
}

func (s *Service) Scrub(ip, method, path string, headers map[string]string, cookies []string, ua string, bodyBytes int) bool {
	if !s.Enabled() {
		return true
	}
	reqBody, _ := json.Marshal(scrubRequest{
		IP:        ip,
		Method:    method,
		Path:      path,
		Headers:   headers,
		Cookies:   cookies,
		UA:        ua,
		BodyBytes: bodyBytes,
	})
	clientRegion := s.regionForIP(ip)
	nodes := s.pickOrder(clientRegion)
	if len(nodes) == 0 {
		return true
	}
	used := 0
	for _, n := range nodes {
		start := time.Now()
		url := n.Node.Host + "/v1/api/peer/scrub"
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		req.Header.SetMethod("POST")
		req.Header.Set("Content-Type", "application/json")
		req.SetRequestURI(url)
		req.SetBodyRaw(reqBody)
		err := s.client.DoTimeout(req, resp, 3*time.Second)
		latency := time.Since(start)
		ok := err == nil && resp.StatusCode() == fasthttp.StatusOK
		if ok {
			var sr scrubResponse
			if json.Unmarshal(resp.Body(), &sr) == nil && !sr.Allow {
				s.updateHealth(n, true, latency)
				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(resp)
				return false
			}
		}
		s.updateHealth(n, ok, latency)
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
		used++
		if !s.multiScrubbing {
			break
		}
	}
	_ = used
	return true
}

func hostIP(host string) string {
	u, err := url.Parse(host)
	if err != nil {
		return ""
	}
	h := u.Host
	if h == "" {
		return ""
	}
	if hp, _, err2 := net.SplitHostPort(h); err2 == nil {
		return hp
	}
	return h
}

func (s *Service) regionForIP(ip string) string {
	if ip == "" {
		return ""
	}
	s.mu.RLock()
	if s.ipRegion != nil {
		if r, ok := s.ipRegion[ip]; ok {
			s.mu.RUnlock()
			return r
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	hc := s.httpClient
	if hc == nil {
		hc = &http.Client{Timeout: 1500 * time.Millisecond}
		s.httpClient = hc
	}
	s.mu.Unlock()

	u := "https://ipapi.co/" + ip + "/continent_code/"
	resp, err := hc.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	buf := make([]byte, 16)
	n, _ := resp.Body.Read(buf)
	if n <= 0 {
		return ""
	}
	code := strings.TrimSpace(string(buf[:n]))
	if code == "" {
		return ""
	}
	if len(code) > 3 {
		code = code[:3]
	}
	s.mu.Lock()
	if s.ipRegion == nil {
		s.ipRegion = map[string]string{}
	}
	s.ipRegion[ip] = code
	s.mu.Unlock()
	return code
}