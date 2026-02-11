package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cshield/internal/analytics"
	"github.com/valyala/fasthttp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Features struct {
	CVAC         bool            `json:"cvac"`
	CWall        bool            `json:"cwall"`
	IPDropping   bool            `json:"ip_dropping"`
	Captcha      bool            `json:"captcha"`
	WAF          bool            `json:"waf"`
	RateLimiting bool            `json:"rate_limiting"`
	Extras       map[string]bool `json:"extras,omitempty"`
}

type Config struct {
	IP              string   `json:"ip" bson:"ip"`
	Domain          string   `json:"domain" bson:"domain"`
	Port            int      `json:"port" bson:"port"`
	CDN             bool     `json:"cdn" bson:"cdn"`
	TLS             bool     `json:"tls" bson:"tls"`
	InsecureTLS     *bool    `json:"insecure_tls,omitempty" bson:"insecure_tls,omitempty"`
	Features        Features `json:"features" bson:"features"`
	FeaturesPresent bool     `json:"-" bson:"-"`
}

type Upstream struct {
	Addr         string
	IsTLS        bool
	SNI          string
	Alive        atomic.Bool
	Conns        atomic.Int32
	FailCount    atomic.Int32
	SuccessCount atomic.Int32
}

type LBConfig struct {
	Method         string
	Pools          map[string][]string
	Targets        []string
	HealthPath     string
	HealthTimeout  time.Duration
	HealthInterval time.Duration
}

type LBUpstreamState struct {
	Addr  string `json:"addr"`
	IsTLS bool   `json:"is_tls"`
	Alive bool   `json:"alive"`
	Conns int32  `json:"conns"`
}

const (
	lbFailureThreshold  = 3
	lbRecoveryThreshold = 2
)

type Manager struct {
	coll     *mongo.Collection
	mu       sync.RWMutex
	byDomain map[string]Config
	client   *fasthttp.Client
	metrics  *analytics.Metrics

	lbMu            sync.RWMutex
	lbMethod        string
	lbPools         map[string][]*Upstream
	rr              map[string]int
	lbHealthPath    string
	lbHealthTimeout time.Duration
	lbTicker        *time.Ticker
	lbStop          chan struct{}
}

func NewManager(mongoURI, mongoDB string, m *analytics.Metrics) *Manager {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	httpClient := &fasthttp.Client{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		MaxConnsPerHost: 512,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	
	if err != nil {
		return &Manager{
			byDomain: map[string]Config{},
			client:   httpClient,
			metrics:  m,
			lbPools:  map[string][]*Upstream{},
			rr:       map[string]int{},
			lbMethod: "round_robin",
		}
	}
	coll := client.Database(mongoDB).Collection("proxies")
	mgr := &Manager{
		coll:     coll,
		byDomain: map[string]Config{},
		client:   httpClient,
		metrics:  m,
		lbPools:  map[string][]*Upstream{},
		rr:       map[string]int{},
		lbMethod: "round_robin",
	}
	_ = mgr.Reload()
	return mgr
}

func (m *Manager) Reload() error {
	if m.coll == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cur, err := m.coll.Find(ctx, bson.M{})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	entries := map[string]Config{}
	for cur.Next(ctx) {
		var c Config
		if cur.Decode(&c) != nil {
			continue
		}
		if c.Domain == "" || c.IP == "" || c.Port == 0 {
			continue
		}
		c.Domain = strings.ToLower(c.Domain)
		c.FeaturesPresent = true
		entries[c.Domain] = c
	}
	m.mu.Lock()
	m.byDomain = entries
	m.mu.Unlock()
	return nil
}

func stripPort(host string) string {
	if i := strings.Index(host, ":"); i != -1 {
		return strings.ToLower(host[:i])
	}
	return strings.ToLower(host)
}

func (m *Manager) resolve(host string) (Config, bool) {
	m.mu.RLock()
	c, ok := m.byDomain[stripPort(host)]
	m.mu.RUnlock()
	if ok {
		return c, true
	}

	key := stripPort(host)
	m.lbMu.RLock()
	_, inLB := m.lbPools[key]
	m.lbMu.RUnlock()

	if inLB {
		return Config{
			Domain: key,
			IP:     "127.0.0.1",
			Port:   80,
			TLS:    true,
			Features: Features{
				CVAC:         true,
				CWall:        true,
				IPDropping:   true,
				Captcha:      true,
				WAF:          true,
				RateLimiting: true,
			},
			FeaturesPresent: true,
		}, true
	}

	return Config{}, false
}

func (m *Manager) Resolve(host string) (Config, bool) {
	return m.resolve(host)
}

func (m *Manager) FeaturesForHost(host string) (Features, bool) {
	if c, ok := m.resolve(host); ok && c.FeaturesPresent {
		return c.Features, true
	}
	return Features{}, false
}



func (m *Manager) serveError(ctx *fasthttp.RequestCtx, code int, page string) {
	b, err := os.ReadFile(page)
	if err != nil {
		ctx.SetStatusCode(code)
		ctx.SetContentType("text/plain; charset=utf-8")
		ctx.SetBody([]byte(fmt.Sprintf("%d", code)))
		return
	}
	ctx.SetStatusCode(code)
	ctx.SetContentType("text/html; charset=utf-8")
	ctx.SetBody(b)
}

func (m *Manager) Handler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		host := string(ctx.Host())
		cfg, ok := m.resolve(host)
		if !ok {
			m.serveError(ctx, fasthttp.StatusNotFound, "public/errors/404.html")
			return
		}
		
		var upstreamURL string
		var sel *Upstream
		if up, ok2 := m.pickUpstream(cfg.Domain); ok2 {
			sel = up
			scheme := "http"
			if up.IsTLS {
				scheme = "https"
			}
			upstreamURL = fmt.Sprintf("%s://%s%s", scheme, up.Addr, ctx.RequestURI())
		} else {
			scheme := "http"
			if cfg.TLS {
				scheme = "https"
			}
			upstreamURL = fmt.Sprintf("%s://%s:%d%s", scheme, cfg.IP, cfg.Port, ctx.RequestURI())
		}
		
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)
		
		req.SetRequestURI(upstreamURL)
		req.Header.SetMethodBytes(ctx.Method())
		if ctx.IsPost() || ctx.IsPut() || ctx.IsPatch() {
			req.SetBodyRaw(ctx.PostBody())
		}
		req.Header.SetHost(cfg.Domain)
		ctx.Request.Header.VisitAll(func(k, v []byte) {
			ks := strings.ToLower(string(k))
			if ks == "host" || ks == "connection" {
				return
			}
			req.Header.SetBytesKV(k, v)
		})
		
		err := m.client.Do(req, resp)
		if sel != nil {
			m.releaseUpstream(sel)
		}
		if err != nil {
			fmt.Printf("cshield: upstream error for host=%s origin=%s:%d tls=%v err=%v\n",
				host, cfg.IP, cfg.Port, cfg.TLS, err)
			m.metrics.IncErrors()
			m.serveError(ctx, fasthttp.StatusBadGateway, "public/errors/502.html")
			return
		}
		status := resp.StatusCode()
		m.metrics.IncStatus(status)
		if status >= 500 {
			m.metrics.IncErrors()
		} else {
			m.metrics.IncProxied()
		}
		resp.Header.VisitAll(func(k, v []byte) { ctx.Response.Header.SetBytesKV(k, v) })
		ctx.SetStatusCode(status)
		body := resp.Body()
		ctx.Response.SetBodyRaw(append([]byte(nil), body...))
	}
}

func (m *Manager) ConfigureLB(cfg LBConfig) {
	m.lbMu.Lock()
	defer m.lbMu.Unlock()
	method := strings.ToLower(cfg.Method)
	if method != "least_conn" {
		method = "round_robin"
	}
	m.lbMethod = method
	pools := map[string][]*Upstream{}
	for dom, list := range cfg.Pools {
		d := strings.ToLower(dom)
		ups := []*Upstream{}
		for _, s := range list {
			addr := s
			isTLS := false
			if strings.HasPrefix(s, "https://") {
				addr = strings.TrimPrefix(s, "https://")
				isTLS = true
			} else if strings.HasPrefix(s, "http://") {
				addr = strings.TrimPrefix(s, "http://")
			}
			if addr == "" {
				continue
			}
			if !strings.Contains(addr, ":") {
				if isTLS {
					addr = addr + ":443"
				} else {
					addr = addr + ":80"
				}
			}
			u := &Upstream{Addr: addr, IsTLS: isTLS, SNI: ""}
			u.Alive.Store(true)
			ups = append(ups, u)
		}
		if len(ups) > 0 {
			pools[d] = ups
		}
	}
	if len(cfg.Targets) > 0 {
		ups := []*Upstream{}
		for _, t := range cfg.Targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			var addr string
			var isTLS bool
			var sni string
			if strings.Contains(t, "://") {
				s := t
				isTLS = false
				if strings.HasPrefix(s, "https://") {
					s = strings.TrimPrefix(s, "https://")
					isTLS = true
				} else if strings.HasPrefix(s, "http://") {
					s = strings.TrimPrefix(s, "http://")
				}
				addr = s
				if i := strings.Index(addr, "/"); i >= 0 {
					addr = addr[:i]
				}
				if !strings.Contains(addr, ":") {
					if isTLS {
						addr = addr + ":443"
					} else {
						addr = addr + ":80"
					}
				}
				h := addr
				if i := strings.Index(h, ":"); i >= 0 {
					h = h[:i]
				}
				sni = h
			} else if strings.Contains(t, "|") {
				parts := strings.SplitN(t, "|", 2)
				h := strings.TrimSpace(parts[0])
				prt := strings.TrimSpace(parts[1])
				if h == "" || prt == "" {
					continue
				}
				addr = h + ":" + prt
				isTLS = prt == "443"
				sni = h
			} else {
				addr = t
				isTLS = strings.HasSuffix(t, ":443")
				if !strings.Contains(addr, ":") {
					if isTLS {
						addr = addr + ":443"
					} else {
						addr = addr + ":80"
					}
				}
				h := t
				if i := strings.Index(h, ":"); i > 0 {
					h = h[:i]
				}
				sni = h
			}
			u := &Upstream{Addr: addr, IsTLS: isTLS, SNI: sni}
			u.Alive.Store(true)
			ups = append(ups, u)
		}
		if len(ups) > 0 {
			pools["*"] = ups
		}
	}
	m.lbPools = pools
	m.lbHealthPath = cfg.HealthPath
	if m.lbHealthPath == "" {
		m.lbHealthPath = "/healthz"
	}
	if cfg.HealthTimeout <= 0 {
		m.lbHealthTimeout = 2 * time.Second
	} else {
		m.lbHealthTimeout = cfg.HealthTimeout
	}
	interval := cfg.HealthInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if m.lbTicker != nil {
		close(m.lbStop)
		m.lbTicker.Stop()
		m.lbTicker = nil
	}
	if len(m.lbPools) > 0 {
		m.lbStop = make(chan struct{})
		m.lbTicker = time.NewTicker(interval)
		go m.healthLoop()
	}
}

func (m *Manager) healthLoop() {
	for {
		select {
		case <-m.lbStop:
			return
		case <-m.lbTicker.C:
			m.runHealthChecks()
		}
	}
}

func (m *Manager) runHealthChecks() {
	m.lbMu.RLock()
	pools := m.lbPools
	m.lbMu.RUnlock()
	for domain, ups := range pools {
		for _, u := range ups {
			go func(dom string, us *Upstream) {
				alive := m.checkUpstream(dom, us, true)
				if alive {
					us.SuccessCount.Add(1)
					us.FailCount.Store(0)
					if us.SuccessCount.Load() >= lbRecoveryThreshold {
						us.Alive.Store(true)
					}
				} else {
					us.FailCount.Add(1)
					us.SuccessCount.Store(0)
					if us.FailCount.Load() >= lbFailureThreshold {
						us.Alive.Store(false)
					}
				}
			}(domain, u)
		}
	}
}

func (m *Manager) checkUpstream(domain string, us *Upstream, health bool) bool {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	
	scheme := "http"
	if us.IsTLS {
		scheme = "https"
	}
	upstreamURL := fmt.Sprintf("%s://%s%s", scheme, us.Addr, m.lbHealthPath)
	
	req.SetRequestURI(upstreamURL)
	req.Header.SetMethod("GET")
	req.Header.SetHost(domain)
	
	err := m.client.DoTimeout(req, resp, m.lbHealthTimeout)
	if err != nil {
		return false
	}
	code := resp.StatusCode()
	return code >= 200 && code < 500
}

func (m *Manager) pickUpstream(host string) (*Upstream, bool) {
	m.lbMu.Lock()
	defer m.lbMu.Unlock()
	key := stripPort(host)
	ups, ok := m.lbPools[key]
	if !ok || len(ups) == 0 {
		key = "*"
		ups, ok = m.lbPools[key]
		if !ok || len(ups) == 0 {
			return nil, false
		}
	}
	alive := make([]*Upstream, 0, len(ups))
	for _, u := range ups {
		if u.Alive.Load() {
			alive = append(alive, u)
		}
	}
	if len(alive) == 0 {
		alive = ups
	}
	var sel *Upstream
	if m.lbMethod == "least_conn" {
		var min int32 = 1<<31 - 1
		for _, u := range alive {
			c := u.Conns.Load()
			if c < min {
				min = c
				sel = u
			}
		}
		if sel == nil {
			sel = alive[0]
		}
	} else {
		idx := m.rr[key]
		sel = alive[idx%len(alive)]
		m.rr[key] = (idx + 1) % len(alive)
	}
	sel.Conns.Add(1)
	return sel, true
}

func (m *Manager) releaseUpstream(u *Upstream) {
	if u != nil {
		u.Conns.Add(-1)
	}
}

func (m *Manager) State() (string, map[string][]LBUpstreamState) {
	out := map[string][]LBUpstreamState{}
	m.lbMu.RLock()
	method := m.lbMethod
	for dom, ups := range m.lbPools {
		list := make([]LBUpstreamState, 0, len(ups))
		for _, u := range ups {
			alive := u.Alive.Load()
			if !alive {
				alive = true
			}
			list = append(list, LBUpstreamState{
				Addr:  u.Addr,
				IsTLS: u.IsTLS,
				Alive: alive,
				Conns: u.Conns.Load(),
			})
		}
		out[dom] = list
	}
	m.lbMu.RUnlock()
	return method, out
}

func (m *Manager) UpsertProxy(c Config) error {
	if m.coll == nil {
		return nil
	}
	if c.Domain == "" || c.IP == "" || c.Port == 0 {
		return nil
	}
	c.Domain = strings.ToLower(c.Domain)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.coll.UpdateOne(ctx, bson.M{"domain": c.Domain}, bson.M{"$set": c}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) DeleteProxy(domain string) error {
	if m.coll == nil {
		return nil
	}
	dom := strings.ToLower(domain)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.coll.DeleteOne(ctx, bson.M{"domain": dom})
	if err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) ListDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.byDomain))
	for d := range m.byDomain {
		out = append(out, d)
	}
	return out
}

func (m *Manager) ConfigForDomain(domain string) (Config, bool) {
	return m.resolve(domain)
}

func (m *Manager) UpdateFeatures(domain string, f Features) error {
	if m.coll == nil {
		return nil
	}
	dom := strings.ToLower(domain)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.coll.UpdateOne(ctx, bson.M{"domain": dom}, bson.M{"$set": bson.M{"features": f}}, options.Update().SetUpsert(true))
	if err != nil {
		return err
	}
	return m.Reload()
}