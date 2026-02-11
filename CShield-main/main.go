package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cshield/internal/analytics"
	"cshield/internal/auth"
	"cshield/internal/cache"
	"cshield/internal/captcha"
	"cshield/internal/core"
	"cshield/internal/cvac"
	"cshield/internal/cwall"
	"cshield/internal/fallback"
	"cshield/internal/geo"
	"cshield/internal/peer"
	"cshield/internal/proxy"
	"cshield/internal/ratelimit"
	"cshield/internal/security"
	"cshield/internal/storage"
	"cshield/internal/waf"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/unix"
	"syscall"
)

type TLSCfg struct {
	Enable   bool   `json:"enable"`
	CacheDir string `json:"cache_dir"`
	Email    string `json:"email"`
	Domain string `json:"domain,omitempty"`
}

type RedisCfg struct {
	Addr     string `json:"addr"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

type MongoCfg struct {
	URI      string `json:"uri"`
	Database string `json:"database"`
}

type MaintenanceCfg struct {
	Enabled    bool   `json:"enabled"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"`
}

type AppConfig struct {
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	Domain    string   `json:"domain,omitempty"`
	TLS       TLSCfg   `json:"tls"`
	ServerKey string   `json:"server_key"`
	Redis     RedisCfg `json:"redis"`
	Mongo     MongoCfg `json:"mongo"`
}

type FeaturesConfig struct {
	CVAC         bool `json:"cvac"`
	CWall        bool `json:"cwall"`
	IPDropping   bool `json:"ip_dropping"`
	ASNBlocking  bool `json:"asn_blocking"`
	Captcha      bool `json:"captcha"`
	WAF          bool `json:"waf"`
	RateLimiting bool `json:"rate_limiting"`
	Peers        bool `json:"peers"`
}

type LoadBalancerConfig struct {
	Method  string              `json:"method"`
	Pools   map[string][]string `json:"pools"`
	Targets []string            `json:"targets"`
	Health  struct {
		Path       string `json:"path"`
		TimeoutMs  int    `json:"timeout_ms"`
		IntervalMs int    `json:"interval_ms"`
	} `json:"health"`
}

type PeersConfig struct {
	SmartRouting   bool        `json:"smart_routing"`
	MultiScrubbing bool        `json:"multi_scrubbing"`
	Peers          []peer.Node `json:"peers"`
}

type TrustedUsersConfig struct {
	IPs []string `json:"ips"`
}

type WAFConfig struct {
	Rules []string `json:"rules"`
}

type PageRulesConfig struct {
	Rules []any `json:"rules"`
}

type RateLimitingConfig struct {
	GlobalRPS int `json:"global_rps"`
	Burst     int `json:"burst"`
	WindowMs  int `json:"window_ms"`
}

type ASNBlockConfig struct {
	ASNs []string `json:"asns"`
}

var (
	asnBlockMu sync.RWMutex
	asnBlock   = map[string]bool{}
)

type LoginUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type LoginConfig struct {
	Users []LoginUser `json:"users"`
}

const (
	dirConfigs = "configs"
	dirPublic  = "public"
	dirErrors  = "public/errors"
)

func genSecret() string {
	b := make([]byte, 64)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func ensureDirs() error {
	if err := os.MkdirAll(dirConfigs, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(dirPublic, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(dirErrors, 0755); err != nil {
		return err
	}
	return nil
}

func writeJSONIfMissing(path string, v any) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func loadOrInitApp() (AppConfig, error) {
	p := filepath.Join(dirConfigs, "app.json")
	var c AppConfig
	if _, err := os.Stat(p); os.IsNotExist(err) {
		c = AppConfig{
			Host:   "0.0.0.0",
			Port:   80,
			Domain: "",
			TLS:    TLSCfg{Enable: false, CacheDir: "acme-cache", Email: "", Domain: ""},
			ServerKey: genSecret(),
			Redis: RedisCfg{
				Addr:     "127.0.0.1:6379",
				Password: "",
				DB:       0,
			},
			Mongo: MongoCfg{
				URI:      "mongodb://127.0.0.1:27017",
				Database: "cshield",
			},
		}
		if err := writeJSONIfMissing(p, c); err != nil {
			return c, err
		}
		applyEnvOverridesApp(&c)
		return c, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Domain == "" && c.TLS.Domain != "" {
		c.Domain = c.TLS.Domain
	}
	c.TLS.Domain = ""
	if c.Redis.Addr == "" {
		c.Redis.Addr = "127.0.0.1:6379"
	}
	if c.Mongo.URI == "" {
		c.Mongo.URI = "mongodb://127.0.0.1:27017"
	}
	if c.Mongo.Database == "" {
		c.Mongo.Database = "cshield"
	}
	if c.ServerKey == "" {
		c.ServerKey = genSecret()
		_ = os.WriteFile(p, mustJSON(c), 0644)
	}
	applyEnvOverridesApp(&c)
	return c, nil
}

func applyEnvOverridesApp(c *AppConfig) {
	if c == nil {
		return
	}
	if v := os.Getenv("CSHIELD_HOST"); v != "" {
		c.Host = v
	}
	if v := os.Getenv("CSHIELD_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			c.Port = p
		}
	}
	if v := os.Getenv("CSHIELD_DOMAIN"); v != "" {
		c.Domain = strings.TrimSpace(v)
	}

	if v := os.Getenv("CSHIELD_TLS_ENABLE"); v != "" {
		l := strings.ToLower(strings.TrimSpace(v))
		if l == "1" || l == "true" || l == "yes" {
			c.TLS.Enable = true
		}
		if l == "0" || l == "false" || l == "no" {
			c.TLS.Enable = false
		}
	}
	if v := os.Getenv("CSHIELD_TLS_CACHE_DIR"); v != "" {
		c.TLS.CacheDir = v
	}
	if v := os.Getenv("CSHIELD_TLS_EMAIL"); v != "" {
		c.TLS.Email = v
	}

	if v := os.Getenv("CSHIELD_SERVER_KEY"); v != "" {
		if len(v) >= 32 {
			c.ServerKey = v
		}
	}

	if v := os.Getenv("CSHIELD_REDIS_ADDR"); v != "" {
		c.Redis.Addr = v
	}
	if v := os.Getenv("CSHIELD_REDIS_PASSWORD"); v != "" {
		c.Redis.Password = v
	}
	if v := os.Getenv("CSHIELD_REDIS_DB"); v != "" {
		if db, err := strconv.Atoi(v); err == nil && db >= 0 {
			c.Redis.DB = db
		}
	}

	if v := os.Getenv("CSHIELD_MONGO_URI"); v != "" {
		c.Mongo.URI = v
	}
	if v := os.Getenv("CSHIELD_MONGO_DB"); v != "" {
		c.Mongo.Database = v
	}
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

func ensureDefaultConfigs() error {
	features := map[string]any{
		"cvac":                  true,
		"asn_blocking":          true,
		"captcha":               true,
		"waf":                   true,
		"rate_limiting":         true,
		"cookie_verification":   true,
		"header_uri_filtering":  true,
		"ua_referrer_blocking":  true,
		"sqli_xss_bad_payload":  true,
		"anti_bypass_detection": true,
		"peers":                 true,
		"page_rules":            true,
		"load_balancer":         true,
		"maintenance":           false,
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "features.json"), features); err != nil {
		return err
	}
	lb := LoadBalancerConfig{Method: "round_robin", Pools: map[string][]string{}, Targets: []string{}}
	lb.Health.Path = "/healthz"
	lb.Health.TimeoutMs = 2000
	lb.Health.IntervalMs = 5000
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "load_balancer.json"), lb); err != nil {
		return err
	}
	pc := PeersConfig{
		SmartRouting:   true,
		MultiScrubbing: true,
		Peers:          []peer.Node{},
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "peers.json"), pc); err != nil {
		return err
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "waf.json"), WAFConfig{Rules: []string{}}); err != nil {
		return err
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "page_rules.json"), PageRulesConfig{Rules: []any{}}); err != nil {
		return err
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "rate_limiting.json"),
		RateLimitingConfig{GlobalRPS: 300, Burst: 150, WindowMs: 1000}); err != nil {
		return err
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "login.json"), LoginConfig{Users: []LoginUser{}}); err != nil {
		return err
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "trusted_users.json"),
		TrustedUsersConfig{IPs: []string{}}); err != nil {
		return err
	}
	if err := writeJSONIfMissing(filepath.Join(dirConfigs, "asn_blocks.json"),
		ASNBlockConfig{ASNs: []string{}}); err != nil {
		return err
	}
	return nil
}

func loadFeatures() (FeaturesConfig, error) {
	var f FeaturesConfig
	b, err := os.ReadFile(filepath.Join(dirConfigs, "features.json"))
	if err != nil {
		return f, err
	}
	err = json.Unmarshal(b, &f)
	return f, err
}

func readFeatureFlags(b []byte) map[string]bool {
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return nil
	}
	out := map[string]bool{}
	for k, v := range raw {
		if bv, ok := v.(bool); ok {
			out[k] = bv
		}
	}
	return out
}

func loadBaseExtras() map[string]bool {
	b, err := os.ReadFile(filepath.Join(dirConfigs, "features.json"))
	if err != nil {
		return nil
	}
	return readFeatureFlags(b)
}

func loadMaintenance() MaintenanceCfg {
	out := MaintenanceCfg{
		Enabled:    false,
		Message:    "",
		RetryAfter: 0,
	}
	b, err := os.ReadFile(filepath.Join(dirConfigs, "features.json"))
	if err != nil {
		return out
	}
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return out
	}
	if v, ok := raw["maintenance"].(bool); ok {
		out.Enabled = v
	}
	return out
}
 
func saveMaintenance(cfg MaintenanceCfg) error {
	p := filepath.Join(dirConfigs, "features.json")
	b, err := os.ReadFile(p)
	var raw map[string]any
	if err == nil {
		if json.Unmarshal(b, &raw) != nil {
			raw = map[string]any{}
		}
	} else {
		raw = map[string]any{}
	}
	raw["maintenance"] = cfg.Enabled
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, out, 0644)
}

func loadRateLimiting() (RateLimitingConfig, error) {
	var c RateLimitingConfig
	b, err := os.ReadFile(filepath.Join(dirConfigs, "rate_limiting.json"))
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func loadWAF() (*waf.Engine, error) {
	var cfg WAFConfig
	b, err := os.ReadFile(filepath.Join(dirConfigs, "waf.json"))
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	return waf.New(cfg.Rules), err
}

func loadPeers() (PeersConfig, error) {
	var p PeersConfig
	b, err := os.ReadFile(filepath.Join(dirConfigs, "peers.json"))
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(b, &p)
	return p, err
}

func loadTrustedUsers() (TrustedUsersConfig, error) {
	var c TrustedUsersConfig
	b, err := os.ReadFile(filepath.Join(dirConfigs, "trusted_users.json"))
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func loadLoadBalancer() (LoadBalancerConfig, error) {
	var c LoadBalancerConfig
	b, err := os.ReadFile(filepath.Join(dirConfigs, "load_balancer.json"))
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func loadASNBlocks() {
	path := filepath.Join(dirConfigs, "asn_blocks.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg ASNBlockConfig
	if json.Unmarshal(b, &cfg) != nil {
		var arr []string
		if json.Unmarshal(b, &arr) == nil {
			cfg.ASNs = arr
		} else {
			var m map[string]bool
			if json.Unmarshal(b, &m) == nil {
				for k, v := range m {
					if v {
						cfg.ASNs = append(cfg.ASNs, k)
					}
				}
			}
		}
	}
	m := make(map[string]bool, len(cfg.ASNs))
	for _, raw := range cfg.ASNs {
		asn := strings.ToUpper(strings.TrimSpace(raw))
		if asn == "" {
			continue
		}
		m[asn] = true
	}
	asnBlockMu.Lock()
	asnBlock = m
	asnBlockMu.Unlock()
}

func snapshotASNBlocks() []string {
	asnBlockMu.RLock()
	defer asnBlockMu.RUnlock()
	out := make([]string, 0, len(asnBlock))
	for asn := range asnBlock {
		out = append(out, asn)
	}
	sort.Strings(out)
	return out
}

func setASNBlocked(asn string, blocked bool) {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	if asn == "" {
		return
	}
	asnBlockMu.Lock()
	if asnBlock == nil {
		asnBlock = map[string]bool{}
	}
	if blocked {
		asnBlock[asn] = true
	} else {
		delete(asnBlock, asn)
	}
	path := filepath.Join(dirConfigs, "asn_blocks.json")
	cfg := ASNBlockConfig{ASNs: make([]string, 0, len(asnBlock))}
	for k := range asnBlock {
		cfg.ASNs = append(cfg.ASNs, k)
	}
	sort.Strings(cfg.ASNs)
	_ = os.WriteFile(path, mustJSON(cfg), 0644)
	asnBlockMu.Unlock()
}

func isASNBlocked(asn string) bool {
	asn = strings.ToUpper(strings.TrimSpace(asn))
	if asn == "" {
		return false
	}
	asnBlockMu.RLock()
	defer asnBlockMu.RUnlock()
	return asnBlock[asn]
}

func ensureAdminBootstrap() {
	p := filepath.Join(dirConfigs, "login.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var raw map[string]any
	if json.Unmarshal(b, &raw) != nil {
		return
	}

	if bs, ok := raw["bootstrap_users"]; ok {
		arr, ok := bs.([]any)
		if !ok {
			if v, ok2 := bs.([]interface{}); ok2 {
				arr = v
			}
		}
		users := []LoginUser{}
		for _, it := range arr {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			u, _ := m["username"].(string)
			pw, _ := m["password"].(string)
			if u == "" || pw == "" {
				continue
			}
			users = append(users, LoginUser{Username: u, PasswordHash: pw})
		}
		if len(users) > 0 {
			lc := LoginConfig{Users: users}
			_ = os.WriteFile(p, mustJSON(lc), 0644)
		}
		return
	}

	bu, _ := raw["bootstrap_username"].(string)
	bp, _ := raw["bootstrap_password"].(string)
	if bu == "" || bp == "" {
		return
	}
	lc := LoginConfig{Users: []LoginUser{{Username: bu, PasswordHash: bp}}}
	_ = os.WriteFile(p, mustJSON(lc), 0644)
}

type EdgeInfo struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	ASN      string `json:"asn"`
	Org      string `json:"org"`
	Capital  string `json:"capital"`
	State    string `json:"state"`
	Timezone string `json:"timezone"`
}

func probeEdgeInfo() EdgeInfo {
	cli := &http.Client{Timeout: 3 * time.Second}
	ip := ""
	if resp, err := cli.Get("https://api.ipify.org?format=text"); err == nil {
		if b, e := io.ReadAll(resp.Body); e == nil {
			ip = strings.TrimSpace(string(b))
		}
		if resp.Body != nil {
			resp.Body.Close()
		}
	}
	e := EdgeInfo{IP: ip}
	if ip != "" {
		if resp, err := cli.Get("https://ipapi.co/" + ip + "/json/"); err == nil {
			if b, e2 := io.ReadAll(resp.Body); e2 == nil {
				var m map[string]any
				if json.Unmarshal(b, &m) == nil {
					if v, ok := m["city"].(string); ok {
						e.City = v
					}
					if v, ok := m["region"].(string); ok {
						e.State = v
					}
					if v, ok := m["country_name"].(string); ok {
						e.Country = v
					}
					if v, ok := m["asn"].(string); ok {
						e.ASN = v
					}
					if v, ok := m["org"].(string); ok {
						e.Org = v
					}
					if v, ok := m["country_capital"].(string); ok {
						e.Capital = v
					} else if v, ok := m["capital"].(string); ok {
						e.Capital = v
					}
					if v, ok := m["timezone"].(string); ok {
						e.Timezone = v
						if i := strings.Index(v, "/"); i > 0 {
							e.Region = v[:i]
							if e.Capital == "" && i+1 < len(v) {
								e.Capital = v[i+1:]
							}
						}
					}
					if e.Region == "" {
						if v, ok := m["continent_code"].(string); ok {
							e.Region = v
						}
					}
				}
			}
			if resp.Body != nil {
				resp.Body.Close()
			}
		}
	}
	return e
}

type cpuSample struct {
	idle  uint64
	total uint64
}

var (
	lastCPU     cpuSample
	haveLastCPU bool
	cpuMu       sync.Mutex
)

func readCPUPct() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return -1
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return -1
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return -1
	}

	var idle, total uint64
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return -1
		}
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}

	cpuMu.Lock()
	defer cpuMu.Unlock()
	if !haveLastCPU {
		lastCPU = cpuSample{idle: idle, total: total}
		haveLastCPU = true
		return -1
	}
	dIdle := idle - lastCPU.idle
	dTotal := total - lastCPU.total
	lastCPU = cpuSample{idle: idle, total: total}
	if dTotal == 0 {
		return -1
	}
	usage := (1 - float64(dIdle)/float64(dTotal)) * 100
	if usage < 0 {
		usage = 0
	}
	if usage > 100 {
		usage = 100
	}
	return usage
}

func readMemPct() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	var memTotal, memAvailable uint64
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") || strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			v, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				continue
			}
			if strings.HasPrefix(line, "MemTotal:") {
				memTotal = v
			} else if strings.HasPrefix(line, "MemAvailable:") {
				memAvailable = v
			}
		}
		if memTotal > 0 && memAvailable > 0 {
			break
		}
	}
	if memTotal == 0 {
		return -1
	}
	used := memTotal - memAvailable
	pct := float64(used) / float64(memTotal) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

type trackedConn struct {
	net.Conn
	key string
	tl  *trackingListener
}

func (c *trackedConn) Close() error {
	if c.tl != nil && c.key != "" {
		c.tl.remove(c.key, c)
	}
	return c.Conn.Close()
}

type trackingListener struct {
	net.Listener
	mu    sync.Mutex
	conns map[string]*trackedConn
}

func newTrackingListener(ln net.Listener) *trackingListener {
	return &trackingListener{
		Listener: ln,
		conns:    make(map[string]*trackedConn),
	}
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	key := ""
	if ra := c.RemoteAddr(); ra != nil {
		key = ra.String()
	}
	tc := &trackedConn{Conn: c, key: key, tl: l}
	if key != "" {
		l.mu.Lock()
		l.conns[key] = tc
		l.mu.Unlock()
	}
	return tc, nil
}

func (l *trackingListener) remove(key string, c *trackedConn) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if cur, ok := l.conns[key]; ok && cur == c {
		delete(l.conns, key)
	}
}

func (l *trackingListener) rst(remote string) {
	if remote == "" {
		return
	}
	l.mu.Lock()
	c := l.conns[remote]
	delete(l.conns, remote)
	l.mu.Unlock()
	if c == nil {
		return
	}
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		if raw, err := tcp.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				linger := &unix.Linger{Onoff: 1, Linger: 0}
				_ = unix.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, linger)
			})
		}
	}
	_ = c.Conn.Close()
}

func sseMetricsHandler(m *analytics.Metrics) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Content-Type", "text/event-stream")
		ctx.Response.Header.Set("Cache-Control", "no-cache")
		ctx.Response.Header.Set("X-Accel-Buffering", "no")
		ctx.SetBodyStreamWriter(func(w *bufio.Writer) {
			t := time.NewTicker(1 * time.Second)
			defer t.Stop()
			for {
				_, _ = w.WriteString("event: metrics\n")
				_, _ = w.WriteString("data: ")
				_, _ = w.Write(m.SnapshotJSON())
				_, _ = w.WriteString("\n\n")
				if err := w.Flush(); err != nil {
					return
				}
				<-t.C
			}
		})
	}
}

func jsonReply(ctx *fasthttp.RequestCtx, code int, v any) {
	ctx.Response.Header.Set("Content-Type", "application/json")
	b, _ := json.Marshal(v)
	ctx.SetStatusCode(code)
	ctx.SetBody(b)
}

func listJSONFiles(root string) ([]string, error) {
	out := []string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out, err
}

func safePath(rel string) (string, bool) {
	clean := filepath.Clean(rel)
	if strings.Contains(clean, "..") {
		return "", false
	}
	full := filepath.Join(dirConfigs, clean)
	if !strings.HasPrefix(full, filepath.Clean(dirConfigs)+string(os.PathSeparator)) && full != filepath.Clean(dirConfigs) {
		return "", false
	}
	if !strings.HasSuffix(strings.ToLower(full), ".json") {
		return "", false
	}
	return full, true
}

func main() {
	if err := ensureDirs(); err != nil {
		panic(err)
	}
	if err := ensureDefaultConfigs(); err != nil {
		panic(err)
	}
	loadASNBlocks()
	app, err := loadOrInitApp()
	if err != nil {
		panic(err)
	}

	features, err := loadFeatures()
	if err != nil {
		panic(err)
	}
	baseExtras := loadBaseExtras()
	rlc, err := loadRateLimiting()
	if err != nil {
		panic(err)
	}
	peerCfg, _ := loadPeers()
	trustedCfg, _ := loadTrustedUsers()
	maintenance := loadMaintenance()
	trustedIPs := map[string]bool{}
	for _, ip := range trustedCfg.IPs {
		if ip == "" {
			continue
		}
		trustedIPs[ip] = true
	}
	ensureAdminBootstrap()

	metrics := analytics.New()
	geoRes := geo.NewResolver()
	edgeCache := cache.NewWithRedis(app.Redis.Addr, app.Redis.Password, app.Redis.DB, 4096, 10*time.Second)

	fbStore := fallback.New(app.Redis.Addr, app.Redis.Password, app.Redis.DB)
	fbStore.StartFileRefresher(app.ServerKey, filepath.Join(dirErrors, "edge-down.html"), 5*time.Minute)

	capSvc := captcha.New(app.ServerKey)
	var limiter *ratelimit.Limiter
	if features.RateLimiting {
		limiter = ratelimit.New(rlc.GlobalRPS, rlc.Burst, rlc.WindowMs)
	}

	pm := proxy.NewManager(app.Mongo.URI, app.Mongo.Database, metrics)
	_ = pm.Reload()
	lbOn := true
	if baseExtras != nil {
		if v, ok := baseExtras["load_balancer"]; ok {
			lbOn = v
		}
	}
	if lbConf, err := loadLoadBalancer(); err == nil {
		if lbOn {
			pm.ConfigureLB(proxy.LBConfig{
				Method:         lbConf.Method,
				Pools:          lbConf.Pools,
				Targets:        lbConf.Targets,
				HealthPath:     lbConf.Health.Path,
				HealthTimeout:  time.Duration(lbConf.Health.TimeoutMs) * time.Millisecond,
				HealthInterval: time.Duration(lbConf.Health.IntervalMs) * time.Millisecond,
			})
		} else {
			pm.ConfigureLB(proxy.LBConfig{})
		}
	} else {
		pm.ConfigureLB(proxy.LBConfig{})
	}

	wafEngine, _ := loadWAF()
	cvacEngine := cvac.NewWithMongo(app.Mongo.URI, app.Mongo.Database)
	replay := security.NewReplayStore(256)
	var fw *cwall.Firewall
	fw = cwall.New()
	defer fw.Close()
	st, err := storage.New(app.Redis.Addr, app.Redis.Password, app.Redis.DB, app.Mongo.URI, app.Mongo.Database)
	if err == nil {
		_ = st.Init()
		if st != nil && fw != nil {
			if list, e := st.List(); e == nil {
				now := time.Now().Unix()
				for _, b := range list {
					if b.Permanent || b.ExpiresAt == -1 {
						fw.DropForever(b.IP)
						continue
					}
					if b.ExpiresAt > now {
						ttl := time.Duration(b.ExpiresAt-now) * time.Second
						if ttl <= 0 {
							ttl = time.Hour
						}
						fw.DropShort(b.IP, ttl)
					}
				}
			}
		}
	}

	peerSvc := peer.NewService(peer.Config{
		SmartRouting:   peerCfg.SmartRouting,
		MultiScrubbing: peerCfg.MultiScrubbing,
		Peers:          peerCfg.Peers,
	})

	var gate *core.Gate
	var tl *trackingListener

	r := router.New()
		isShieldHost := func(ctx *fasthttp.RequestCtx) bool {
			host := string(ctx.Host())
			if i := strings.Index(host, ":"); i >= 0 {
				host = host[:i]
			}
			d := strings.ToLower(strings.TrimSpace(app.Domain))
			if d == "" {
				return false
			}
			return strings.EqualFold(strings.ToLower(host), d)
		}
		fsHandler := (&fasthttp.FS{Root: "./public", GenerateIndexPages: false, Compress: true}).NewRequestHandler()

	r.GET("/healthz", func(ctx *fasthttp.RequestCtx) { ctx.Success("text/plain", []byte("ok")) })
	r.GET("/sse/metrics", sseMetricsHandler(metrics))
	r.GET("/v1/api/metrics", func(ctx *fasthttp.RequestCtx) { ctx.Success("application/json", metrics.SnapshotJSON()) })
	edge := probeEdgeInfo()
	r.GET("/v1/api/edge/info", func(ctx *fasthttp.RequestCtx) { jsonReply(ctx, fasthttp.StatusOK, edge) })
	r.GET("/v1/api/system/health", func(ctx *fasthttp.RequestCtx) {
		cpu := readCPUPct()
		mem := readMemPct()
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{
			"cpu_pct": cpu,
			"mem_pct": mem,
		})
	})

	r.POST("/v1/api/captcha/new", capSvc.NewChallengeHandler())
	r.POST("/v1/api/captcha/verify", capSvc.VerifyHandler())
	r.POST("/v1/api/login", func(ctx *fasthttp.RequestCtx) {
		if !isShieldHost(ctx) {
			pm.Handler()(ctx)
			return
		}
		auth.LoginHandler(app.ServerKey)(ctx)
	})

	r.POST("/v1/api/peer/scrub", func(ctx *fasthttp.RequestCtx) {
		var req struct {
			IP        string            `json:"ip"`
			Method    string            `json:"method"`
			Path      string            `json:"path"`
			Headers   map[string]string `json:"headers"`
			Cookies   []string          `json:"cookies"`
			UA        string            `json:"ua"`
			BodyBytes int               `json:"body_bytes"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		if cvacEngine == nil {
			jsonReply(ctx, fasthttp.StatusOK, map[string]any{"allow": true})
			return
		}
		hdrs := []string{}
		for k := range req.Headers {
			hdrs = append(hdrs, k)
		}
		info := cvac.RequestInfo{
			Path:      req.Path,
			Method:    req.Method,
			Headers:   hdrs,
			Cookies:   req.Cookies,
			UserAgent: req.UA,
			BodyBytes: req.BodyBytes,
			IsLogin:   req.Path == "/login" || req.Path == "/v1/api/login",
			Now:       time.Now(),
		}
		ob := cvacEngine.ObserveRequest(req.IP, info)
		allow := true
		if ob.RateJump || ob.ImpossibleTiming || ob.HighEntropy || ob.RuleAction != "" {
			allow = false
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"allow": allow})
	})

	admin := func(h fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			if !isShieldHost(ctx) {
				pm.Handler()(ctx)
				return
			}
			ip := security.ClientIP(ctx)
			if trustedIPs[ip] {
				h(ctx)
				return
			}
			auth.RequireAdmin(app.ServerKey, h)(ctx)
		}
	}

	r.GET("/v1/api/analytics/attacks", admin(func(ctx *fasthttp.RequestCtx) {
		// Small Redis-backed cache so repeated dashboard refreshes don't
		// recompute geo data for every attack row.
		const cachePath = "/__admin__/analytics/attacks"
		if edgeCache != nil && len(ctx.QueryArgs().QueryString()) == 0 {
			if ent, ok := edgeCache.Get("", cachePath, "GET", "", false); ok {
				ctx.Response.Header.Set("Content-Type", "application/json")
				ctx.SetStatusCode(ent.Status)
				ctx.SetBody(ent.Body)
				return
			}
		}

		events := metrics.AttackSnapshot()
		type Row struct {
			Time        int64   `json:"time"`
			IP          string  `json:"ip"`
			Path        string  `json:"path"`
			Method      string  `json:"method"`
			UA          string  `json:"ua"`
			Reason      string  `json:"reason"`
			Action      string  `json:"action"`
			Score       int     `json:"score"`
			Status      int     `json:"status"`
			Country     string  `json:"country"`
			CountryCode string  `json:"country_code"`
			City        string  `json:"city"`
			Region      string  `json:"region"`
			Lat         float64 `json:"lat"`
			Lon         float64 `json:"lon"`
		}
		out := make([]Row, 0, len(events))
		for _, e := range events {
			row := Row{
				Time:   e.Time,
				IP:     e.IP,
				Path:   e.Path,
				Method: e.Method,
				UA:     e.UA,
				Reason: e.Reason,
				Action: e.Action,
				Score:  e.Score,
				Status: e.Status,
			}

			// First try live geo lookup
			if info, ok := geoRes.Lookup(e.IP); ok {
				row.Country = info.Country
				row.CountryCode = info.CountryCode
				row.City = info.City
				row.Region = info.Region
				row.Lat = info.Lat
				row.Lon = info.Lon

				// Also persist basic meta so that if future lookups fail,
				// analytics can still show a non-"Unknown" country.
				if st != nil && (info.Country != "" || info.CountryCode != "") {
					st.SetMeta(e.IP, storage.Meta{
						IP:          e.IP,
						Country:     info.Country,
						CountryCode: info.CountryCode,
						ASN:         info.ASN,
						Org:         info.Org,
					}, 0)
				}
			} else if st != nil {
				// Fallback: reuse last known country from Redis meta cache.
				if meta, ok2 := st.GetMeta(e.IP); ok2 {
					row.Country = meta.Country
					row.CountryCode = meta.CountryCode
				}
			}

			out = append(out, row)
		}
		resp := map[string]any{"events": out}
		b, _ := json.Marshal(resp)
		ctx.Response.Header.Set("Content-Type", "application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(b)

		if edgeCache != nil && len(ctx.QueryArgs().QueryString()) == 0 {
			edgeCache.Set("", cachePath, "GET", "", false, fasthttp.StatusOK, b,
				map[string]string{"Content-Type": "application/json"})
		}
	}))

	r.GET("/v1/api/analytics/geo", func(ctx *fasthttp.RequestCtx) {
		// Cache geo snapshot for a short period to avoid recomputing
		// and re-querying geo providers on every dashboard refresh.
		const cachePath = "/__admin__/analytics/geo"
		if edgeCache != nil && len(ctx.QueryArgs().QueryString()) == 0 {
			if ent, ok := edgeCache.Get("", cachePath, "GET", "", false); ok {
				ctx.Response.Header.Set("Content-Type", "application/json")
				ctx.SetStatusCode(ent.Status)
				ctx.SetBody(ent.Body)
				return
			}
		}

		stats := metrics.IPStatsSnapshot()
		type Point struct {
			IP          string  `json:"ip"`
			Requests    uint64  `json:"requests"`
			Attacks     uint64  `json:"attacks"`
			LastSeen    int64   `json:"last_seen"`
			Country     string  `json:"country"`
			CountryCode string  `json:"country_code"`
			City        string  `json:"city"`
			Region      string  `json:"region"`
			Lat         float64 `json:"lat"`
			Lon         float64 `json:"lon"`
			ASN         string  `json:"asn"`
			Org         string  `json:"org"`
			Timezone    string  `json:"timezone"`
		}
		points := make([]Point, 0, len(stats))
		countries := map[string]uint64{}
		for ip, ipst := range stats {
			if ipst.Requests == 0 {
				continue
			}
			info, ok := geoRes.Lookup(ip)
			if !ok {
				continue
			}
			var risk int64
			if st != nil {
				risk = st.GetIPRisk(ip)
				st.SetMeta(ip, storage.Meta{
					IP:          ip,
					Country:     info.Country,
					CountryCode: info.CountryCode,
					ASN:         info.ASN,
					Org:         info.Org,
					Risk:        risk,
				}, 0)
			}
			points = append(points, Point{
				IP:          ip,
				Requests:    ipst.Requests,
				Attacks:     ipst.Attacks,
				LastSeen:    ipst.Last,
				Country:     info.Country,
				CountryCode: info.CountryCode,
				City:        info.City,
				Region:      info.Region,
				Lat:         info.Lat,
				Lon:         info.Lon,
				ASN:         info.ASN,
				Org:         info.Org,
				Timezone:    info.Timezone,
			})
			if info.CountryCode != "" {
				countries[info.CountryCode] += ipst.Requests
			}
		}
		sort.Slice(points, func(i, j int) bool {
			return points[i].Requests > points[j].Requests
		})
		if len(points) > 200 {
			points = points[:200]
		}
		resp := map[string]any{
			"countries": countries,
			"points":    points,
		}
		b, _ := json.Marshal(resp)
		ctx.Response.Header.Set("Content-Type", "application/json")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(b)

		if edgeCache != nil && len(ctx.QueryArgs().QueryString()) == 0 {
			edgeCache.Set("", cachePath, "GET", "", false, fasthttp.StatusOK, b,
				map[string]string{"Content-Type": "application/json"})
		}
	})
	
	r.POST("/v1/api/cvac/check", admin(func(ctx *fasthttp.RequestCtx) {
		if cvacEngine == nil {
			jsonReply(ctx, fasthttp.StatusServiceUnavailable, map[string]any{
				"ok":    false,
				"error": "cvac_disabled",
			})
			return
		}
	
		ip := security.ClientIP(ctx)
	
		headers := []string{}
		ctx.Request.Header.VisitAll(func(k, v []byte) {
			headers = append(headers, string(k))
		})
		cookies := []string{}
		ctx.Request.Header.VisitAllCookie(func(k, v []byte) {
			cookies = append(cookies, string(k)+"="+string(v))
		})
	
		info := cvac.RequestInfo{
			Path:      string(ctx.Path()),
			Method:    string(ctx.Method()),
			Headers:   headers,
			Cookies:   cookies,
			UserAgent: string(ctx.UserAgent()),
			BodyBytes: len(ctx.Request.Body()),
			IsLogin:   string(ctx.Path()) == "/login" || string(ctx.Path()) == "/v1/api/login",
			Now:       time.Now(),
		}
	
		ob := cvacEngine.ObserveRequest(ip, info)
		score := cvacEngine.Score(ip)
	
		action := "allow"
		if ob.PredictedScore >= 95 {
			action = "block_forever"
		} else if ob.PredictedScore >= 90 {
			action = "block_short"
		} else if ob.PredictedScore >= 70 {
			action = "captcha"
		}
	
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{
			"ok":     true,
			"ip":     ip,
			"score":  score,
			"result": ob,
			"action": action,
		})
	}))
	
	r.GET("/v1/api/configs/list", admin(func(ctx *fasthttp.RequestCtx) {
		names, err := listJSONFiles(dirConfigs)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"files": names})
	}))

	r.GET("/v1/api/configs/read", admin(func(ctx *fasthttp.RequestCtx) {
		p := string(ctx.QueryArgs().Peek("path"))
		full, ok := safePath(p)
		if !ok {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		b, err := os.ReadFile(full)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			return
		}
		if filepath.Base(full) == "app.json" {
			var c AppConfig
			if json.Unmarshal(b, &c) == nil {
				if c.Domain == "" && c.TLS.Domain != "" {
					c.Domain = c.TLS.Domain
				}
				c.TLS.Domain = ""
				b = mustJSON(c)
			}
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"path": p, "content": string(b)})
	}))

	r.POST("/v1/api/configs/save", admin(func(ctx *fasthttp.RequestCtx) {
		var req struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		full, ok := safePath(req.Path)
		if !ok {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		base := filepath.Base(full)
		var pretty []byte
		if base == "app.json" {
			var nc AppConfig
			if json.Unmarshal([]byte(req.Content), &nc) != nil {
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
				return
			}
			if nc.Domain == "" && nc.TLS.Domain != "" {
				nc.Domain = nc.TLS.Domain
			}
			nc.TLS.Domain = ""
			if nc.ServerKey == "" {
				nc.ServerKey = app.ServerKey
			}
			app = nc
			if gate != nil {
				gate.Secret = app.ServerKey
				gate.ShieldDomain = app.Domain
			}
			pretty = mustJSON(app)
		} else {
			var tmp any
			if json.Unmarshal([]byte(req.Content), &tmp) != nil {
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
				return
			}
			pretty, _ = json.MarshalIndent(tmp, "", "  ")
		}
		if err := os.WriteFile(full, pretty, 0644); err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		if base == "features.json" {
			var nf FeaturesConfig
			if json.Unmarshal([]byte(req.Content), &nf) == nil {
				old := features
				features = nf
				if old.RateLimiting != nf.RateLimiting {
					if nf.RateLimiting {
						limiter = ratelimit.New(rlc.GlobalRPS, rlc.Burst, rlc.WindowMs)
					} else {
						limiter = nil
					}
				}
				if gate != nil {
					gate.Limiter = limiter
					gate.RateLimitRPS = rlc.GlobalRPS
					gate.RateLimitWindowMs = rlc.WindowMs
				}
				if gate != nil {
					gate.FW = fw
					gate.CaptchaEnabled = nf.Captcha
					gate.WAFEnabled = nf.WAF
					gate.CVACEnabled = nf.CVAC
					gate.PeersEnabled = nf.Peers
				}
				be := readFeatureFlags([]byte(req.Content))
				if be != nil {
					baseExtras = be
					if gate != nil {
						gate.BaseExtras = be
					}
					lbOn := true
					if v, ok := be["load_balancer"]; ok {
						lbOn = v
					}
					if lbOn {
						if lbConf, err2 := loadLoadBalancer(); err2 == nil {
							pm.ConfigureLB(proxy.LBConfig{
								Method:         lbConf.Method,
								Pools:          lbConf.Pools,
								Targets:        lbConf.Targets,
								HealthPath:     lbConf.Health.Path,
								HealthTimeout:  time.Duration(lbConf.Health.TimeoutMs) * time.Millisecond,
								HealthInterval: time.Duration(lbConf.Health.IntervalMs) * time.Millisecond,
							})
						}
					} else {
						pm.ConfigureLB(proxy.LBConfig{})
					}
				}
				mc := loadMaintenance()
				if gate != nil {
					gate.MaintenanceEnabled = mc.Enabled
					gate.MaintenanceMsg = mc.Message
					gate.MaintenanceRetry = mc.RetryAfter
				}
			}
		}

		if base == "rate_limiting.json" {
			var nr RateLimitingConfig
			if json.Unmarshal([]byte(req.Content), &nr) == nil {
				rlc = nr
				if features.RateLimiting {
					limiter = ratelimit.New(rlc.GlobalRPS, rlc.Burst, rlc.WindowMs)
				} else {
					limiter = nil
				}
				if gate != nil {
					gate.Limiter = limiter
					gate.RateLimitRPS = rlc.GlobalRPS
					gate.RateLimitWindowMs = rlc.WindowMs
				}
			}
		}

		if base == "load_balancer.json" {
			var lb LoadBalancerConfig
			if json.Unmarshal([]byte(req.Content), &lb) == nil {
				lbOn := true
				if baseExtras != nil {
					if v, ok := baseExtras["load_balancer"]; ok {
						lbOn = v
					}
				}
				if lbOn {
					pm.ConfigureLB(proxy.LBConfig{
						Method:         lb.Method,
						Pools:          lb.Pools,
						Targets:        lb.Targets,
						HealthPath:     lb.Health.Path,
						HealthTimeout:  time.Duration(lb.Health.TimeoutMs) * time.Millisecond,
						HealthInterval: time.Duration(lb.Health.IntervalMs) * time.Millisecond,
					})
				} else {
					pm.ConfigureLB(proxy.LBConfig{})
				}
			}
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	r.POST("/v1/api/proxies/add", admin(func(ctx *fasthttp.RequestCtx) {
		var c proxy.Config
		body := ctx.PostBody()
		if err := json.Unmarshal(body, &c); err != nil {
			jsonReply(ctx, fasthttp.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "bad_json",
			})
			return
		}
		if c.Domain == "" || c.IP == "" || c.Port == 0 {
			jsonReply(ctx, fasthttp.StatusBadRequest, map[string]any{
				"ok":     false,
				"error":  "missing_fields",
				"domain": c.Domain,
				"ip":     c.IP,
				"port":   c.Port,
				"raw":    string(body),
			})
			return
		}
		if err := pm.UpsertProxy(c); err != nil {
			jsonReply(ctx, fasthttp.StatusInternalServerError, map[string]any{
				"ok":    false,
				"error": "upsert_failed",
			})
			return
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	r.POST("/v1/api/proxies/reload", admin(func(ctx *fasthttp.RequestCtx) {
		_ = pm.Reload()
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	r.GET("/v1/api/proxies/list", admin(func(ctx *fasthttp.RequestCtx) {
		names := pm.ListDomains()
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"files": names})
	}))

	r.GET("/v1/api/lb/state", admin(func(ctx *fasthttp.RequestCtx) {
		method, pools := pm.State()
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"method": method, "pools": pools})
	}))

	r.GET("/v1/api/peers/state", admin(func(ctx *fasthttp.RequestCtx) {
		stats := peerSvc.Stats()
		cfg := len(stats)
		on := 0
		for _, n := range stats {
			if n.Healthy {
				on++
			}
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{
			"enabled":         features.Peers && peerSvc.Enabled(),
			"smart_routing":   peerCfg.SmartRouting,
			"multi_scrubbing": peerCfg.MultiScrubbing,
			"configured":      cfg,
			"online":          on,
			"nodes":           stats,
		})
	}))

	r.GET("/v1/api/bans/list", admin(func(ctx *fasthttp.RequestCtx) {
		if st == nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			return
		}
		// Bans list now exposes recent TCP connection resets instead of
		// persistent Mongo bans. This avoids relying on Mongo and reflects
		// the new "no long-lived bans" model.
		resets, err := st.ListResets(200)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"resets": resets})
	}))
	
	r.POST("/v1/api/bans/block", admin(func(ctx *fasthttp.RequestCtx) {
		if st == nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			return
		}
		var req struct {
			IP        string `json:"ip"`
			TTL       int64  `json:"ttl_sec"`
			Permanent bool   `json:"permanent"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil || strings.TrimSpace(req.IP) == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		ip := strings.TrimSpace(req.IP)
		ttl := req.TTL
		if ttl <= 0 {
			ttl = 3600
		}
		// Manual admin block is now a temporary Redis flag + reset record.
		// There are no persistent Mongo bans or CWall iptables rules anymore.
		st.MarkTempBlocked(ip, time.Duration(ttl)*time.Second)
		st.RecordReset(ip)
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{
			"ok":      true,
			"ip":      ip,
			"ttl_sec": ttl,
			"mode":    "temp_block",
		})
	}))
	
	r.POST("/v1/api/bans/unban", admin(func(ctx *fasthttp.RequestCtx) {
		if st == nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			return
		}
		var req struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil || strings.TrimSpace(req.IP) == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		ip := strings.TrimSpace(req.IP)
		_ = st.ClearReset(ip)
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))
	
	r.GET("/v1/api/bans/get", admin(func(ctx *fasthttp.RequestCtx) {
		if st == nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			return
		}
		ip := strings.TrimSpace(string(ctx.QueryArgs().Peek("ip")))
		if ip == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		rs, ok, err := st.GetReset(ip)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		if !ok {
			jsonReply(ctx, fasthttp.StatusOK, map[string]any{"found": false})
			return
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{
			"found": true,
			"reset": rs,
		})
	}))
	
	r.POST("/v1/api/bans/clear-all", admin(func(ctx *fasthttp.RequestCtx) {
		if st == nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			return
		}
		if err := st.ClearAllResets(); err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	r.GET("/v1/api/asn-blocks/list", admin(func(ctx *fasthttp.RequestCtx) {
		asns := snapshotASNBlocks()
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"asns": asns})
	}))

	r.POST("/v1/api/asn-blocks/block", admin(func(ctx *fasthttp.RequestCtx) {
		var req struct {
			ASN string `json:"asn"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		asn := strings.ToUpper(strings.TrimSpace(req.ASN))
		if asn == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		setASNBlocked(asn, true)
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	r.POST("/v1/api/asn-blocks/unblock", admin(func(ctx *fasthttp.RequestCtx) {
		var req struct {
			ASN string `json:"asn"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		asn := strings.ToUpper(strings.TrimSpace(req.ASN))
		if asn == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		setASNBlocked(asn, false)
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	r.GET("/v1/api/proxies/get", admin(func(ctx *fasthttp.RequestCtx) {
		domain := string(ctx.QueryArgs().Peek("domain"))
		if domain == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		cfg, ok := pm.ConfigForDomain(domain)
		if !ok {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			return
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"domain": strings.ToLower(domain), "content": string(b)})
	}))

	r.POST("/v1/api/proxies/set-features", admin(func(ctx *fasthttp.RequestCtx) {
		var req struct {
			Domain   string         `json:"domain"`
			Features proxy.Features `json:"features"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil || req.Domain == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		if err := pm.UpdateFeatures(req.Domain, req.Features); err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	r.POST("/v1/api/proxies/delete", admin(func(ctx *fasthttp.RequestCtx) {
		var req struct {
			Domain string `json:"domain"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil || req.Domain == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		if err := pm.DeleteProxy(req.Domain); err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))
	r.GET("/add_proxy.html", admin(func(ctx *fasthttp.RequestCtx) {
		fasthttp.ServeFile(ctx, "public/add_proxy.html")
	}))
	r.GET("/proxies.html", admin(func(ctx *fasthttp.RequestCtx) {
		fasthttp.ServeFile(ctx, "public/proxies.html")
	}))
	r.GET("/features.html", admin(func(ctx *fasthttp.RequestCtx) {
		fasthttp.ServeFile(ctx, "public/features.html")
	}))
	r.GET("/logs.html", admin(func(ctx *fasthttp.RequestCtx) {
		fasthttp.ServeFile(ctx, "public/logs.html")
	}))
	r.GET("/analytics.html", admin(func(ctx *fasthttp.RequestCtx) {
		fasthttp.ServeFile(ctx, "public/analytics.html")
	}))

	r.GET("/login", func(ctx *fasthttp.RequestCtx) {
		if !isShieldHost(ctx) {
			pm.Handler()(ctx)
			return
		}
		ip := security.ClientIP(ctx)
		if trustedIPs[ip] {
			ctx.Redirect("/dashboard", fasthttp.StatusFound)
			return
		}
		if p, ok := security.ReadAndVerify(ctx, app.ServerKey); ok && p.Role == "admin" {
			ctx.Redirect("/dashboard", fasthttp.StatusFound)
			return
		}
		fasthttp.ServeFile(ctx, "public/login.html")
	})
	r.GET("/captcha.html", func(ctx *fasthttp.RequestCtx) {
		fasthttp.ServeFile(ctx, "public/captcha.html")
	})
	authPage := func(file string) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			if !isShieldHost(ctx) {
				pm.Handler()(ctx)
				return
			}
			ip := security.ClientIP(ctx)
			if trustedIPs[ip] {
				fasthttp.ServeFile(ctx, file)
				return
			}
			p, ok := security.ReadAndVerify(ctx, app.ServerKey)
			if !ok || p.Role != "admin" {
				ctx.Redirect("/login", fasthttp.StatusFound)
				return
			}
			fasthttp.ServeFile(ctx, file)
		}
	}
	r.GET("/dashboard", authPage("public/dashboard.html"))
	r.GET("/settings", authPage("public/settings.html"))
	r.GET("/add_proxy", authPage("public/add_proxy.html"))
	r.GET("/proxies", authPage("public/proxies.html"))
	r.GET("/features", authPage("public/features.html"))
	r.GET("/logs", authPage("public/logs.html"))
	r.GET("/analytics", authPage("public/analytics.html"))

	r.GET("/public/{filepath:*}", fsHandler)

	r.NotFound = pm.Handler()

	gate = &core.Gate{
		Secret:         app.ServerKey,
		CaptchaEnabled: features.Captcha,
		Limiter:        limiter,
		Metrics:        metrics,
		RateLimitRPS:      rlc.GlobalRPS,
		RateLimitWindowMs: rlc.WindowMs,
		WAFEnabled: features.WAF,
		WAF:        wafEngine,
		CVACEnabled:       features.CVAC,
		CVAC:              cvacEngine,
		PeersEnabled:      features.Peers,
		Replay:     replay,
		FW:         fw,
		Peer:       peerSvc,
		ProxyMgr:   pm,
		Store:      st,
		Cache:      edgeCache,
		BaseExtras: baseExtras,
		TrustedIPs: trustedIPs,
		MaintenanceEnabled: maintenance.Enabled,
		MaintenanceMsg:     maintenance.Message,
		MaintenanceRetry:   maintenance.RetryAfter,
		ShieldDomain: app.Domain,
		ResetConn: func(ctx *fasthttp.RequestCtx) {
			if ctx == nil {
				return
			}
			if tl == nil {
				ctx.SetConnectionClose()
				return
			}
			ra := ctx.RemoteAddr()
			if ra == nil {
				ctx.SetConnectionClose()
				return
			}
			tl.rst(ra.String())
		},
	}

	r.GET("/v1/api/maintenance/get", admin(func(ctx *fasthttp.RequestCtx) {
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{
			"enabled":     gate.MaintenanceEnabled,
			"message":     gate.MaintenanceMsg,
			"retry_after": gate.MaintenanceRetry,
		})
	}))
	r.POST("/v1/api/maintenance/set", admin(func(ctx *fasthttp.RequestCtx) {
		var req struct {
			Enabled    bool   `json:"enabled"`
			Message    string `json:"message"`
			RetryAfter int    `json:"retry_after"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		gate.MaintenanceEnabled = req.Enabled
		gate.MaintenanceMsg = req.Message
		gate.MaintenanceRetry = req.RetryAfter
		_ = saveMaintenance(MaintenanceCfg{
			Enabled:    req.Enabled,
			Message:    req.Message,
			RetryAfter: req.RetryAfter,
		})
		jsonReply(ctx, fasthttp.StatusOK, map[string]any{"ok": true})
	}))

	baseHandler := gate.Middleware(r.Handler)

	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			defer func() {
				if rec := recover(); rec != nil {
					if html, _ := fbStore.GetHTML(app.ServerKey); len(html) > 0 {
						ctx.Response.Reset()
						ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
						ctx.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
						ctx.SetBody(html)
						return
					}
					panic(rec)
				}
				code := ctx.Response.StatusCode()
				if code == fasthttp.StatusBadGateway || code == fasthttp.StatusGatewayTimeout {
					if html, _ := fbStore.GetHTML(app.ServerKey); len(html) > 0 {
						ctx.Response.Reset()
						ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
						ctx.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
						ctx.SetBody(html)
					}
				}
			}()

			if features.ASNBlocking {
				ip := security.ClientIP(ctx)
				if ip != "" {
					if info, ok := geoRes.Lookup(ip); ok {
						if isASNBlocked(info.ASN) {
							ctx.Response.Reset()
							ctx.SetStatusCode(fasthttp.StatusForbidden)
							ctx.Response.Header.Set("Content-Type", "text/plain; charset=utf-8")
							ctx.SetBody([]byte("Blocked by ASN policy"))
							return
						}
					}
				}
			}

			baseHandler(ctx)
		},
		Name:              "CShield",
		MaxRequestBodySize: 1 << 20,
	}

	if app.TLS.Enable && app.Domain != "" {
		if err := os.MkdirAll(app.TLS.CacheDir, 0755); err != nil {
			panic(err)
		}
		hostPolicy := func(_ context.Context, host string) error {
			h := strings.ToLower(strings.TrimSpace(host))
			if h == "" {
				return fmt.Errorf("empty host")
			}
			d := strings.ToLower(strings.TrimSpace(app.Domain))
			if d != "" && h == d {
				return nil
			}
			if cfg, ok := pm.ConfigForDomain(h); ok && cfg.TLS {
				return nil
			}
			return fmt.Errorf("unauthorized host %s", host)
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(app.TLS.CacheDir),
			Email:      app.TLS.Email,
			HostPolicy: hostPolicy,
		}
		go http.ListenAndServe(":80", m.HTTPHandler(nil))
		ln, err := net.Listen("tcp", ":443")
		if err != nil {
			panic(err)
		}
		tl = newTrackingListener(ln)
		tc := m.TLSConfig()
		tc.NextProtos = []string{acme.ALPNProto, "http/1.1"}
		err = s.Serve(tls.NewListener(tl, tc))
		if err != nil {
			panic(err)
		}
		return
	}
	addr := fmt.Sprintf("%s:%d", app.Host, app.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	tl = newTrackingListener(ln)
	if err := s.Serve(tl); err != nil {
		panic(err)
	}
}