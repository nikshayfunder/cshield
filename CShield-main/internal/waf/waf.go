package waf

import (
	"bytes"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/valyala/fasthttp"
)

type Decision int

const (
	Allow Decision = iota
	Captcha
	Throttle
	Block
)

type Engine struct {
	rxSQLi []*regexp.Regexp
	rxXSS  []*regexp.Regexp
	rxBad  []*regexp.Regexp
}

func New(extraRules []string) *Engine {
	sql := []string{
		`(?i)(union(\s+all)?\s+select)`,
		`(?i)(select\s+.+\s+from)`,
		`(?i)(or|and)\s+1\s*=\s*1`,
		`(?i)information_schema`,
		`(?i)(sleep\()`,
		`(?i)(updatexml|extractvalue)\s*\(`,
		`(?i)(load_file|outfile)\s*\(`,
		`(?i)xp_cmdshell`,
	}
	xss := []string{
		`(?i)<\s*script\b`,
		`(?i)onerror\s*=`,
		`(?i)onload\s*=`,
		`(?i)javascript:`,
		`(?i)src\s*=\s*data:text/html`,
	}
	bad := []string{
		`(?i)\.\./\.\./`,
		`(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)`,
		`(?i)(\%3C)|(<).+(\%3E)|(>)`,
	}
	for _, r := range extraRules {
		if strings.TrimSpace(r) == "" {
			continue
		}
		bad = append(bad, r)
	}
	return &Engine{
		rxSQLi: mustCompile(sql),
		rxXSS:  mustCompile(xss),
		rxBad:  mustCompile(bad),
	}
}

func mustCompile(ps []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(ps))
	for _, p := range ps {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		rx, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		out = append(out, rx)
	}
	return out
}

func uaQuality(ua string) int {
	l := strings.ToLower(ua)
	if l == "" {
		return 0
	}
	botSig := []string{
		"censys", "censysinspect", "shodan", "zgrab", "masscan", "nmap", "sqlmap", "nikto",
		"wpscan", "dirbuster", "whatweb", "fuff", "ffuf", "go-http-client", "python-requests",
		"libwww-perl", "java/", "curl", "wget", "awvs", "nessus", "acunetix", "netcraft",
	}
	for _, s := range botSig {
		if strings.Contains(l, s) {
			return -50
		}
	}
	if strings.Contains(l, "mozilla/5.0") {
		return 20
	}
	if strings.Contains(l, "safari") || strings.Contains(l, "chrome") || strings.Contains(l, "firefox") || strings.Contains(l, "edge") {
		return 15
	}
	return 5
}

func headerPresent(v []byte) bool { return len(bytes.TrimSpace(v)) > 0 }

func acceptEncodingBasic(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "identity" {
		return true
	}
	if v == "gzip" || v == "br" {
		return true
	}
	return false
}

func pathEntropy(p []byte) float64 {
	if len(p) == 0 {
		return 0
	}
	m := map[rune]int{}
	var total int
	for len(p) > 0 {
		r, size := utf8.DecodeRune(p)
		if r == utf8.RuneError && size == 1 {
			break
		}
		m[r]++
		total++
		p = p[size:]
	}
	e := 0.0
	for _, c := range m {
		pc := float64(c) / float64(total)
		e += -pc * (math.Log(pc) / math.Log(2))
	}
	return e
}

func headerOrderAnomaly(ctx *fasthttp.RequestCtx) bool {
	hdr := &ctx.Request.Header
	order := []string{}
	hdr.VisitAll(func(k, v []byte) {
		ks := strings.ToLower(string(k))
		if ks == "cookie" {
			return
		}
		order = append(order, ks)
	})
	if len(order) == 0 {
		return true
	}
	idxHost := -1
	limit := len(order)
	if limit > 12 {
		limit = 12
	}
	for i := 0; i < limit; i++ {
		if order[i] == "host" {
			idxHost = i
			break
		}
	}
	if idxHost == -1 || idxHost > 2 {
		return true
	}
	expected := []string{"host", "connection", "upgrade-insecure-requests", "user-agent", "accept", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language"}
	expIdx := map[string]int{}
	for i, k := range expected {
		expIdx[k] = i
	}
	unknown := 0
	outOfOrder := 0
	last := -1
	for i := 0; i < limit; i++ {
		k := order[i]
		idx, ok := expIdx[k]
		if !ok {
			unknown++
			continue
		}
		if last > idx {
			outOfOrder++
		}
		last = idx
	}
	if unknown >= limit/2 || outOfOrder >= 3 {
		return true
	}
	return false
}

func (e *Engine) Inspect(ctx *fasthttp.RequestCtx) Decision {
	score := 0

	ua := string(ctx.UserAgent())
	score += -uaQuality(ua)

	if !headerPresent(ctx.Request.Header.Peek("Accept")) || !headerPresent(ctx.Request.Header.Peek("Accept-Language")) {
		score += 15
	}
	if acceptEncodingBasic(string(ctx.Request.Header.Peek("Accept-Encoding"))) {
		score += 10
	}
	if headerOrderAnomaly(ctx) {
		score += 50
	}

	ref := string(ctx.Referer())
	lref := strings.ToLower(ref)
	if ref == "" || strings.HasPrefix(lref, "http://localhost") || strings.HasPrefix(lref, "http://127.0.0.1") {
		score += 20
	}

	if ctx.IsPost() || ctx.IsPut() || ctx.IsPatch() {
		if ctx.IsPost() && ctx.Request.Header.ContentLength() > 2_000_000 && uaQuality(ua) <= 5 {
			return Block
		}
		if ctx.Request.Header.ContentLength() > 1_000_000 && uaQuality(ua) <= 5 {
			score += 30
		}
		ct := strings.ToLower(string(ctx.Request.Header.ContentType()))
		if !strings.Contains(ct, "json") && !strings.Contains(ct, "form") && !strings.Contains(ct, "text") {
			score += 10
		}
	}

	q := string(ctx.URI().QueryString())
	path := string(ctx.Path())
	target := path + "?" + q

	for _, r := range e.rxSQLi {
		if r.MatchString(target) {
			score += 60
			break
		}
	}
	for _, r := range e.rxXSS {
		if r.MatchString(target) {
			score += 60
			break
		}
	}
	for _, r := range e.rxBad {
		if r.MatchString(target) {
			score += 30
			break
		}
	}

	if len(ctx.Path()) > 64 && pathEntropy(ctx.Path()) > 4.8 {
		return Captcha
	}
	if len(ctx.Path()) > 48 && pathEntropy(ctx.Path()) > 4.2 {
		score += 35
	}

	if score >= 100 {
		return Block
	}
	if score >= 60 {
		return Captcha
	}
	if score >= 40 {
		return Throttle
	}
	return Allow
}

func (e *Engine) Test(target string) map[string]any {
	sqli := false
	for _, r := range e.rxSQLi {
		if r.MatchString(target) {
			sqli = true
			break
		}
	}
	xss := false
	for _, r := range e.rxXSS {
		if r.MatchString(target) {
			xss = true
			break
		}
	}
	bad := false
	for _, r := range e.rxBad {
		if r.MatchString(target) {
			bad = true
			break
		}
	}
	score := 0
	if sqli {
		score += 60
	}
	if xss {
		score += 60
	}
	if bad {
		score += 30
	}
	return map[string]any{"sqli": sqli, "xss": xss, "bad": bad, "score": score}
}