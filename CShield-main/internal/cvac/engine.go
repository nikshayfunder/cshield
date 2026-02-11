package cvac

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

type ipState struct {
	windowStart int64
	count       int
	lastRate    float64
	lastMs      int64
	fastStreak  int
	failCookies int
	score       int
	lastScoreTs int64
	total       int64
	firstSeen   int64
	lastSeen    int64
	sigRate     float64
	sigFast     float64
	sigCookie   float64
	sigEntropy  float64
	sigMethod   float64
	sigPath     float64
	methods     map[string]int
	paths       map[string]int
}

type sessState struct {
	fp string
}

type fpState struct {
	count    int
	bad      int
	ips      map[string]struct{}
	lastSeen int64
}

type autoRuleMatch struct {
	Path        string `json:"path,omitempty" bson:"path,omitempty"`
	Method      string `json:"method,omitempty" bson:"method,omitempty"`
	IP          string `json:"ip,omitempty" bson:"ip,omitempty"`
	IPRepeated  bool   `json:"ip_repeated,omitempty" bson:"ip_repeated,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty" bson:"fingerprint,omitempty"`
}

type autoRule struct {
	Rule   string        `json:"rule" bson:"rule"`
	Match  autoRuleMatch `json:"match" bson:"match"`
	Action string        `json:"action" bson:"action"`
}

type RequestInfo struct {
	Path      string
	Method    string
	Headers   []string
	Cookies   []string
	UserAgent string
	BodyBytes int
	IsLogin   bool
	Now       time.Time
}

type Weights struct {
	RateJump       float64
	FastTiming     float64
	CookieFail     float64
	HighEntropy    float64
	MethodAnomaly  float64
	SuspiciousPath float64
	NewFingerprint float64
	FPBadness      float64
}

type Engine struct {
	mu     sync.Mutex
	byIP   map[string]*ipState
	bySess map[string]*sessState
	byFP   map[string]*fpState

	jumpPct    float64
	weights    Weights
	recentHigh []int64
	defconUntil int64
}

type ObserveResult struct {
	RateJump         bool
	ImpossibleTiming bool
	FailCookies      int
	Fingerprint      string
	HighEntropy      bool
	RuleAction       string
	Score            int
	PredictedScore   int
	IPSeenBefore     bool
	AvgReqRate       float64
	IsNewFingerprint bool
	MethodAnomaly    bool
	SuspiciousPath   bool
	ReasonTags       []string
	TrustLevel       int
	FastStreak       int
}

func New() *Engine {
	return NewWithMongo("", "")
}

func NewWithMongo(mongoURI, mongoDB string) *Engine {
	return &Engine{
		byIP:    map[string]*ipState{},
		bySess:  map[string]*sessState{},
		byFP:    map[string]*fpState{},
		jumpPct: 0.25,
		weights: Weights{
			RateJump:       8,
			FastTiming:     8,
			CookieFail:     6,
			HighEntropy:    6,
			MethodAnomaly:  4,
			SuspiciousPath: 4,
			NewFingerprint: 3,
			FPBadness:      3,
		},
	}
}

func NewWithPaths(logPath, ruleDir string) *Engine {
	return New()
}

func (e *Engine) ip(ip string) *ipState {
	st, ok := e.byIP[ip]
	if !ok {
		st = &ipState{}
		e.byIP[ip] = st
	}
	return st
}

func (e *Engine) sess(id string) *sessState {
	ss, ok := e.bySess[id]
	if !ok {
		ss = &sessState{}
		e.bySess[id] = ss
	}
	return ss
}

func (e *Engine) fp(id string) *fpState {
	fs, ok := e.byFP[id]
	if !ok {
		fs = &fpState{ips: map[string]struct{}{}}
		e.byFP[id] = fs
	}
	return fs
}

func lowerSlice(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.ToLower(v)
	}
	return out
}

func makeFingerprint(headers []string, ua string, cookies []string) string {
	if len(headers) == 0 && len(cookies) == 0 && ua == "" {
		return ""
	}
	h := sha256.New()
	for _, v := range headers {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	h.Write([]byte("|"))
	h.Write([]byte(ua))
	h.Write([]byte("|"))
	for _, v := range cookies {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func highPathEntropy(path string) bool {
	if len(path) < 12 {
		return false
	}
	total := 0
	uniq := map[byte]struct{}{}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			total++
			uniq[c] = struct{}{}
		}
	}
	if total < 8 {
		return false
	}
	ratio := float64(len(uniq)) / float64(total)
	return ratio > 0.7
}


func (e *Engine) Observe(ip string) ObserveResult {
	return e.ObserveRequest(ip, RequestInfo{})
}

func (e *Engine) ObserveRequest(ip string, info RequestInfo) ObserveResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := info.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowS := now.Unix()
	nowMs := now.UnixMilli()

	st := e.ip(ip)
	if st.windowStart == 0 {
		st.windowStart = nowS
	}
	if st.firstSeen == 0 {
		st.firstSeen = nowS
	}
	st.lastSeen = nowS
	st.total++

	ipSeenBefore := st.total > 1

	st.count++
	dur := nowS - st.windowStart
	jump := false
	if dur >= 3 {
		rate := float64(st.count) / float64(dur)
		base := st.lastRate
		if base > 0 && rate > base*(1.0+e.jumpPct) {
			jump = true
		}
		alpha := 0.7
		if st.lastRate == 0 {
			st.lastRate = rate
		} else {
			st.lastRate = alpha*rate + (1-alpha)*st.lastRate
		}
		st.windowStart = nowS
		st.count = 0
	}

	fast := false
	if st.lastMs > 0 && nowMs-st.lastMs < 40 {
		st.fastStreak++
		if st.fastStreak >= 3 {
			fast = true
		}
	} else {
		if st.fastStreak > 0 {
			st.fastStreak--
		}
	}
	st.lastMs = nowMs

	headersLower := lowerSlice(info.Headers)
	cookiesLower := lowerSlice(info.Cookies)

	fp := ""
	isNewFP := false
	var fs *fpState
	if len(headersLower) > 0 || len(cookiesLower) > 0 || info.UserAgent != "" {
		fp = makeFingerprint(headersLower, info.UserAgent, cookiesLower)
		if fp != "" {
			fs = e.fp(fp)
			prev := fs.count
			fs.count++
			fs.lastSeen = nowS
			if fs.ips == nil {
				fs.ips = map[string]struct{}{}
			}
			fs.ips[ip] = struct{}{}
			if prev == 0 {
				isNewFP = true
			}
		}
	}

	highEnt := false
	if info.Path != "" {
		if highPathEntropy(info.Path) {
			highEnt = true
		}
	}

	method := strings.ToUpper(info.Method)
	methodAnomaly := false
	if method != "" {
		if st.methods == nil {
			st.methods = map[string]int{}
		}
		totalMethods := 0
		for _, c := range st.methods {
			totalMethods += c
		}
		prev := st.methods[method]
		if ipSeenBefore && totalMethods >= 10 && prev == 0 {
			if method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" {
				methodAnomaly = true
			}
		}
		st.methods[method] = prev + 1
	}

	suspiciousPath := false
	if info.Path != "" {
		if st.paths == nil {
			st.paths = map[string]int{}
		}
		pc := st.paths[info.Path]
		if ipSeenBefore && pc == 0 && len(st.paths) >= 3 {
			suspiciousPath = true
		}
		st.paths[info.Path] = pc + 1
	}

	decay := 0.9
	st.sigRate *= decay
	st.sigFast *= decay
	st.sigCookie *= decay
	st.sigEntropy *= decay
	st.sigMethod *= decay
	st.sigPath *= decay

	if jump {
		st.sigRate += 1
	}
	if fast {
		st.sigFast += 1
	}
	if st.failCookies > 0 {
		st.sigCookie = float64(st.failCookies)
	}
	if highEnt {
		st.sigEntropy += 1
	}
	if methodAnomaly {
		st.sigMethod += 1
	}
	if suspiciousPath {
		st.sigPath += 1
	}

	w := e.weights
	raw := w.RateJump*st.sigRate +
		w.FastTiming*st.sigFast +
		w.CookieFail*st.sigCookie +
		w.HighEntropy*st.sigEntropy +
		w.MethodAnomaly*st.sigMethod +
		w.SuspiciousPath*st.sigPath

	if isNewFP {
		raw += w.NewFingerprint
	}
	if fs != nil && fs.count > 0 && len(fs.ips) > 1 {
		raw += w.FPBadness
	}

	trustLevel := 0
	if st.total > 5 {
		trustLevel = 1
	}
	if st.total > 20 && st.failCookies == 0 && !highEnt {
		trustLevel = 2
	}
	if st.total > 100 && st.failCookies == 0 {
		trustLevel = 3
	}

	factor := 1.0
	if trustLevel == 1 {
		factor = 0.9
	} else if trustLevel == 2 {
		factor = 0.75
	} else if trustLevel == 3 {
		factor = 0.6
	}
	raw = raw * factor

	nowScoreTs := nowS
	if st.lastScoreTs > 0 {
		if nowScoreTs-st.lastScoreTs > 60 {
			raw = raw * 0.7
		}
	}

	if raw < 0 {
		raw = 0
	}

	if raw > 0 {
		if raw >= 80 {
			e.recentHigh = append(e.recentHigh, nowS)
		}
		cut := nowS - 10
		n := 0
		for _, ts := range e.recentHigh {
			if ts >= cut {
				e.recentHigh[n] = ts
				n++
			}
		}
		e.recentHigh = e.recentHigh[:n]
		if len(e.recentHigh) >= 5 {
			e.defconUntil = nowS + 10
		}
	}

	if e.defconUntil != 0 && nowS <= e.defconUntil {
		raw = raw * 1.2
	}

	if raw > 100 {
		raw = 100
	}

	score := int(raw + 0.5)
	if score < 0 {
		score = 0
	}
	st.score = score
	st.lastScoreTs = nowScoreTs

	pred := score
	if jump || fast || highEnt || methodAnomaly || suspiciousPath {
		pred += 5
		if pred > 100 {
			pred = 100
		}
	}

	reasonTags := []string{}
	if jump {
		reasonTags = append(reasonTags, "burst_behavior")
	}
	if fast {
		reasonTags = append(reasonTags, "fast_timing")
	}
	if st.failCookies > 0 {
		reasonTags = append(reasonTags, "cookie_fail")
	}
	if highEnt {
		reasonTags = append(reasonTags, "high_entropy_path")
	}
	if methodAnomaly {
		reasonTags = append(reasonTags, "method_anomaly")
	}
	if suspiciousPath {
		reasonTags = append(reasonTags, "suspicious_path")
	}
	if isNewFP {
		reasonTags = append(reasonTags, "new_fingerprint")
	}

	return ObserveResult{
		RateJump:         jump,
		ImpossibleTiming: fast,
		FailCookies:      st.failCookies,
		Fingerprint:      fp,
		HighEntropy:      highEnt,
		RuleAction:       "",
		Score:            score,
		PredictedScore:   pred,
		IPSeenBefore:     ipSeenBefore,
		AvgReqRate:       st.lastRate,
		IsNewFingerprint: isNewFP,
		MethodAnomaly:    methodAnomaly,
		SuspiciousPath:   suspiciousPath,
		ReasonTags:       reasonTags,
		TrustLevel:       trustLevel,
		FastStreak:       st.fastStreak,
	}
}

func (e *Engine) FailCookie(ip string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.ip(ip)
	st.failCookies++
	return st.failCookies
}

func (e *Engine) ResetCookieFails(ip string) {
	e.mu.Lock()
	e.ip(ip).failCookies = 0
	e.mu.Unlock()
}

func (e *Engine) FingerprintChanged(sessID, fp string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ss := e.sess(sessID)
	if ss.fp == "" {
		ss.fp = fp
		return false
	}
	if ss.fp != fp {
		ss.fp = fp
		return true
	}
	return false
}

func (e *Engine) ResetSession(sessID string) {
	e.mu.Lock()
	delete(e.bySess, sessID)
	e.mu.Unlock()
}

func (e *Engine) Bump(ip string, s int) int {
	if s <= 0 {
		return e.Score(ip)
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	st := e.ip(ip)
	now := time.Now().Unix()
	if st.lastScoreTs > 0 {
		if now-st.lastScoreTs > 30 {
			st.score = int(float64(st.score) * 0.6)
		}
	}
	st.score += s
	if st.score > 100 {
		st.score = 100
	}
	st.lastScoreTs = now
	if st.score < 0 {
		st.score = 0
	}
	return st.score
}

func (e *Engine) Score(ip string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ip(ip).score
}