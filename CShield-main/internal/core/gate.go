package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
 
	"cshield/internal/analytics"
	"cshield/internal/cache"
	"cshield/internal/captcha"
	"cshield/internal/cvac"
	"cshield/internal/cwall"
	"cshield/internal/peer"
	"cshield/internal/proxy"
	"cshield/internal/ratelimit"
	"cshield/internal/security"
	"cshield/internal/storage"
	"cshield/internal/waf"
	"github.com/valyala/fasthttp"
)

type Gate struct {
	Secret         string
	CaptchaEnabled bool
	Limiter        *ratelimit.Limiter
	Metrics        *analytics.Metrics

	RateLimitRPS      int
	RateLimitWindowMs int

	WAFEnabled bool
	WAF        *waf.Engine

	CVACEnabled  bool
	CVAC         *cvac.Engine
	PeersEnabled bool

	Replay    *security.ReplayStore
	FW        *cwall.Firewall
	Peer      *peer.Service
	ProxyMgr  *proxy.Manager
	Store     *storage.Store
	Cache     *cache.Store
	ResetConn func(ctx *fasthttp.RequestCtx)

	BaseExtras map[string]bool
	TrustedIPs map[string]bool

	MaintenanceEnabled bool
	MaintenanceMsg     string
	MaintenanceRetry   int

	ShieldDomain string
}

func (g *Gate) isTrusted(ip string) bool {
	if g.TrustedIPs == nil {
		return false
	}
	return g.TrustedIPs[ip]
}

func (g *Gate) allowPath(p string) bool {
	if p == "/healthz" || strings.HasPrefix(p, "/sse/") {
		return true
	}
	if p == "/v1/api/login" || p == "/login" {
		return true
	}
	if strings.HasPrefix(p, "/v1/api/captcha/") {
		return true
	}
	if p == "/dashboard.html" || p == "/settings.html" || p == "/add_proxy.html" || p == "/proxies.html" || p == "/dashboard" || p == "/settings" || p == "/add_proxy" || p == "/proxies" {
		return true
	}
	if strings.HasPrefix(p, "/v1/api/configs/") || strings.HasPrefix(p, "/v1/api/proxies/") || strings.HasPrefix(p, "/v1/api/bans/") || strings.HasPrefix(p, "/v1/api/maintenance/") || strings.HasPrefix(p, "/v1/api/lb/") || strings.HasPrefix(p, "/v1/api/waf/") || strings.HasPrefix(p, "/v1/api/peers/") || p == "/v1/api/metrics" || p == "/v1/api/edge/info" || p == "/v1/api/peer/scrub" {
		return true
	}
	if strings.HasPrefix(p, "/public/") || p == "/login.html" || p == "/captcha.html" {
		return true
	}
	return false
}

func isStaticPath(p string) bool {
	if p == "" {
		return false
	}
	if i := strings.Index(p, "?"); i >= 0 {
		p = p[:i]
	}
	i := strings.LastIndex(p, ".")
	if i == -1 {
		return false
	}
	ext := strings.ToLower(p[i+1:])
	switch ext {
	case "css", "js", "mjs", "jsx", "ts", "tsx",
		"png", "jpg", "jpeg", "gif", "webp", "ico", "svg",
		"woff", "woff2", "ttf", "otf", "map":
		return true
	default:
		return false
	}
}

func appCompatPath(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "/api/") && strings.Contains(p, "discord") {
		return true
	}
	return false
}

func (g *Gate) redirectToCaptcha(ctx *fasthttp.RequestCtx, ip string) {
	if g.Metrics != nil {
		g.Metrics.IncCaptcha()
	}
	if g.Store != nil && ip != "" {
		g.Store.MarkCaptcha(ip, 0)
	}
	ref := string(ctx.URI().RequestURI())
	if ref == "" {
		ref = "/"
	}
	target := "/captcha.html?r=" + ref
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Redirect(target, fasthttp.StatusFound)
}

func (g *Gate) serveFileOrStatus(ctx *fasthttp.RequestCtx, code int, path string, fallbackMsg string) {
	if b, err := os.ReadFile(path); err == nil {
		ctx.SetStatusCode(code)
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetBody(b)
		return
	}
	ctx.SetStatusCode(code)
	ctx.SetContentType("text/plain; charset=utf-8")
	ctx.SetBodyString(fallbackMsg)
}


func modernBrowser(ua string) bool {
	l := strings.ToLower(ua)
	if l == "" {
		return false
	}
	if strings.Contains(l, "chrome") || strings.Contains(l, "firefox") || strings.Contains(l, "safari") || strings.Contains(l, "edg") {
		return true
	}
	return false
}

func hasGzipOrBr(ctx *fasthttp.RequestCtx) bool {
	v := strings.ToLower(string(ctx.Request.Header.Peek("Accept-Encoding")))
	return strings.Contains(v, "gzip") || strings.Contains(v, "br")
}

func languageSuspicious(ctx *fasthttp.RequestCtx) bool {
	v := strings.ToLower(string(ctx.Request.Header.Peek("Accept-Language")))
	if v == "" {
		return true
	}
	good := []string{"en", "es", "fr", "de", "ru", "zh", "ja", "ko", "ar", "pt", "it", "nl", "tr", "hi", "ta", "si", "ro", "pl", "uk", "vi"}
	for _, g := range good {
		if strings.HasPrefix(v, g) {
			return false
		}
	}
	return true
}

func (g *Gate) signedPayloadMalformed(ctx *fasthttp.RequestCtx) bool {
	pb := ctx.Request.Header.Cookie("cshield_p")
	vb := ctx.Request.Header.Cookie("cshield_v")
	if len(pb) == 0 || len(vb) == 0 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(pb))
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, []byte(g.Secret))
	h.Write(raw)
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	if sig != string(vb) {
		return false
	}
	var tmp map[string]any
	if json.Unmarshal(raw, &tmp) != nil {
		return true
	}
	return false
}

func (g *Gate) softThrottle(ms int) {
	if ms <= 0 {
		return
	}
	if g.Metrics != nil {
		g.Metrics.IncThrottled()
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func (g *Gate) throttle(ctx *fasthttp.RequestCtx) {
	if g.Metrics != nil {
		g.Metrics.IncThrottled()
	}
	ctx.Response.Header.Set("Retry-After", "3")
	g.serveFileOrStatus(ctx, fasthttp.StatusTooManyRequests, "public/errors/429.html", "too many requests")
}

func (g *Gate) forbidden(ctx *fasthttp.RequestCtx) {
	g.Metrics.IncBlocked()
	g.serveFileOrStatus(ctx, fasthttp.StatusForbidden, "public/errors/403.html", "forbidden")
}

func (g *Gate) logAttack(ctx *fasthttp.RequestCtx, ip, reason, action string, score int) {
	if g.Metrics == nil {
		return
	}
	ev := analytics.AttackEvent{
		Time:   time.Now().Unix(),
		IP:     ip,
		Path:   string(ctx.Path()),
		Method: string(ctx.Method()),
		UA:     string(ctx.UserAgent()),
		Reason: reason,
		Action: action,
		Score:  score,
		Status: ctx.Response.StatusCode(),
	}
	g.Metrics.AddAttack(ev)
	g.Metrics.MarkAttack(ip)
	if g.Store != nil {
		g.Store.BumpIPRisk(ip, 1)
		g.Store.EnqueueIPLog(ev)
	}
}

func (g *Gate) rst(ctx *fasthttp.RequestCtx) bool {
	if g.ResetConn == nil || ctx == nil {
		return false
	}
	// Attribute this reset to the client IP for analytics.
	ip := security.ClientIP(ctx)
	if ip != "" && g.Store != nil {
		g.Store.RecordReset(ip)
	}
	// Treat TCP RST mitigations as "blocked" in metrics so the dashboard
	// reflects connection resets as mitigations, not only 403 responses.
	if g.Metrics != nil {
		g.Metrics.IncBlocked()
		g.Metrics.IncDropped()
	}
	g.ResetConn(ctx)
	return true
}

func (g *Gate) actByScore(ip string, score int, toggles proxy.Features, ctx *fasthttp.RequestCtx) bool {
	if g.isTrusted(ip) {
		return false
	}
	if score >= 95 {
		g.logAttack(ctx, ip, "cvac_score", "rst", score)
		if g.rst(ctx) {
			return true
		}
		g.forbidden(ctx)
		return true
	}
	if score >= 90 {
		if toggles.Captcha && !g.isTrusted(ip) {
			g.logAttack(ctx, ip, "cvac_score", "captcha", score)
			g.redirectToCaptcha(ctx, ip)
			return true
		}
		g.logAttack(ctx, ip, "cvac_score", "monitor", score)
		return false
	}
	if score >= 70 && toggles.Captcha && !g.isTrusted(ip) {
		g.logAttack(ctx, ip, "cvac_score", "captcha", score)
		g.redirectToCaptcha(ctx, ip)
		return true
	}
	return false
}

func (g *Gate) bump(ip string, delta int, toggles proxy.Features, ctx *fasthttp.RequestCtx) bool {
	if g.CVAC == nil || !g.CVACEnabled {
		return false
	}
	ns := g.CVAC.Bump(ip, delta)
	return g.actByScore(ip, ns, toggles, ctx)
}

func (g *Gate) Middleware(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if g.Metrics != nil {
			g.Metrics.IncRequests()
		}
		ip := security.ClientIP(ctx)
		if g.Metrics != nil {
			g.Metrics.RecordIP(ip)
		}
		if g.Store != nil {
			g.Store.RecordIP(ip)
		}
		method := string(ctx.Method())
		p := string(ctx.Path())
		if g.allowPath(p) {
			next(ctx)
			return
		}
		if appCompatPath(p) {
			next(ctx)
			return
		}
		if isStaticPath(p) {
			next(ctx)
			return
		}
		rateKey := ip
		if g.Metrics != nil {
			g.Metrics.AddBytesIn(len(ctx.Request.Body()))
		}

		host := string(ctx.Host())
		hNoPort := host
		if i := strings.Index(hNoPort, ":"); i >= 0 {
			hNoPort = hNoPort[:i]
		}
		if net.ParseIP(hNoPort) != nil {
			g.logAttack(ctx, ip, "direct_ip", "block", 0)
			g.serveFileOrStatus(ctx, fasthttp.StatusForbidden, "public/errors/direct-ip.html", "access blocked")
			return
		}
	
		if g.isTrusted(ip) {
			next(ctx)
			return
		}

		// Per-proxy feature flags:
		// - features.json now controls CShield dashboard / global availability.
		// - Actual request handling for a host is driven by the proxy's own
		//   features section stored in Mongo, if present.
		var toggles proxy.Features
		if g.ProxyMgr != nil {
			if pf, ok := g.ProxyMgr.FeaturesForHost(host); ok {
				toggles = pf
			}
		}
		// Fallback when there is no explicit proxy config: derive defaults from
		// global availability so the edge still behaves sensibly.
		if !toggles.CVAC && !toggles.Captcha && !toggles.WAF && !toggles.RateLimiting && toggles.Extras == nil {
			toggles = proxy.Features{
				CVAC:         g.CVACEnabled,
				CWall:        false,
				IPDropping:   false,
				Captcha:      g.CaptchaEnabled,
				WAF:          g.WAFEnabled,
				RateLimiting: g.Limiter != nil || g.Store != nil,
			}
		}
		// Ensure we never enable features that don't have backing engines.
		if toggles.CVAC && g.CVAC == nil {
			toggles.CVAC = false
		}
		if toggles.WAF && g.WAF == nil {
			toggles.WAF = false
		}
		if toggles.RateLimiting && g.Limiter == nil && g.Store == nil {
			toggles.RateLimiting = false
		}
		throttleOn := toggles.RateLimiting
		
		flags := map[string]bool{}
		if g.BaseExtras != nil {
			for k, v := range g.BaseExtras {
				flags[k] = v
			}
		}
		has := func(n string) bool {
			if v, ok := flags[n]; ok {
				return v
			}
			return false
		}

		hasValidCookie := false
		if has("cookie_verification") {
			if _, ok := security.ReadAndVerify(ctx, g.Secret); ok {
				hasValidCookie = true
			}
		}

		if toggles.CVAC && g.CVAC != nil && !hasValidCookie {
			s := g.CVAC.Score(ip)
			if s > 0 {
				if g.actByScore(ip, s, toggles, ctx) {
					return
				}
			}
		}
	
		fp := ""
		isBot := false
	
		if toggles.CVAC && g.CVAC != nil {
			headers := []string{}
			ctx.Request.Header.VisitAll(func(k, v []byte) {
				headers = append(headers, string(k))
			})
			cookies := []string{}
			ctx.Request.Header.VisitAllCookie(func(k, v []byte) {
				cookies = append(cookies, string(k))
			})
			info := cvac.RequestInfo{
				Path:      p,
				Method:    method,
				Headers:   headers,
				Cookies:   cookies,
				UserAgent: string(ctx.UserAgent()),
				BodyBytes: len(ctx.Request.Body()),
				IsLogin:   p == "/login" || p == "/v1/api/login",
				Now:       time.Now(),
			}
			ob := g.CVAC.ObserveRequest(ip, info)
			if !modernBrowser(string(ctx.UserAgent())) && ob.FastStreak > 2 {
				if g.bump(ip, 50, toggles, ctx) {
					return
				}
			}
			if ob.PredictedScore >= 90 && !hasValidCookie {
				if g.actByScore(ip, ob.PredictedScore, toggles, ctx) {
					return
				}
			}
			fp = ob.Fingerprint
			if fp != "" {
				rateKey = "fp:" + fp
			}
			suspicious := ob.RateJump || ob.ImpossibleTiming || ob.HighEntropy
			if suspicious && g.PeersEnabled && g.Peer != nil && g.Peer.Enabled() && p != "/v1/api/peer/scrub" {
				hm := map[string]string{}
				ctx.Request.Header.VisitAll(func(k, v []byte) {
					hm[string(k)] = string(v)
				})
				ck := []string{}
				ctx.Request.Header.VisitAllCookie(func(k, v []byte) {
					ck = append(ck, string(k)+"="+string(v))
				})
				if !g.Peer.Scrub(ip, method, p, hm, ck, string(ctx.UserAgent()), len(ctx.Request.Body())) {
					if g.bump(ip, 80, toggles, ctx) {
						return
					}
					if g.CaptchaEnabled && !g.isTrusted(ip) {
						g.logAttack(ctx, ip, "peer_scrub", "captcha", ob.PredictedScore)
						g.redirectToCaptcha(ctx, ip)
					} else {
						g.logAttack(ctx, ip, "peer_scrub", "throttle", ob.PredictedScore)
						g.softThrottle(300)
						if throttleOn {
							g.throttle(ctx)
							return
						}
					}
					return
				}
			}
			if ob.RateJump {
				if g.bump(ip, 50, toggles, ctx) {
					return
				}
				reason := "rate_jump"
				if len(ob.ReasonTags) > 0 {
					reason = "rate_jump:" + strings.Join(ob.ReasonTags, ",")
				}
				if g.CaptchaEnabled && !g.isTrusted(ip) {
					g.logAttack(ctx, ip, reason, "captcha", ob.PredictedScore)
					g.softThrottle(250)
					g.redirectToCaptcha(ctx, ip)
					return
				}
				g.logAttack(ctx, ip, reason, "throttle", ob.PredictedScore)
				g.softThrottle(250)
				if throttleOn {
					g.throttle(ctx)
					return
				}
				return
			}
			if ob.ImpossibleTiming {
				if g.bump(ip, 60, toggles, ctx) {
					return
				}
				reason := "impossible_timing"
				if len(ob.ReasonTags) > 0 {
					reason = "impossible_timing:" + strings.Join(ob.ReasonTags, ",")
				}
				g.logAttack(ctx, ip, reason, "throttle", ob.PredictedScore)
				g.softThrottle(500)
				if throttleOn {
					g.throttle(ctx)
					return
				}
				return
			}
			if ob.HighEntropy {
				if g.bump(ip, 30, toggles, ctx) {
					return
				}
				reason := "high_entropy"
				if len(ob.ReasonTags) > 0 {
					reason = "high_entropy:" + strings.Join(ob.ReasonTags, ",")
				}
				if g.CaptchaEnabled && !g.isTrusted(ip) {
					g.logAttack(ctx, ip, reason, "captcha", ob.PredictedScore)
					g.redirectToCaptcha(ctx, ip)
					return
				}
				g.logAttack(ctx, ip, reason, "monitor", ob.PredictedScore)
				return
			}
		}

		qa := ctx.URI().QueryArgs()
		if qa.Has("cshield_force_captcha") && g.CaptchaEnabled && !g.isTrusted(ip) {
			g.logAttack(ctx, ip, "force_captcha", "captcha", 0)
			g.redirectToCaptcha(ctx, ip)
			return
		}
		if qa.Has("__cf_chl_rt_tk") || qa.Has("__c_chl_rt_tk") {
			tok := string(qa.Peek("__c_chl_rt_tk"))
			if tok == "" {
				tok = string(qa.Peek("__cf_chl_rt_tk"))
			}
			okTok := false
			if tok != "" {
				okTok = captcha.ValidateToken(g.Secret, tok, ctx)
			}
			if okTok || g.isTrusted(ip) {
				qa.Del("__cf_chl_rt_tk")
				qa.Del("__c_chl_rt_tk")
				newURI := string(ctx.Path())
				if qa.Len() > 0 {
					newURI = newURI + "?" + qa.String()
				}
				ctx.Response.Header.Set("Cache-Control", "no-store")
				ctx.Redirect(newURI, fasthttp.StatusFound)
				return
			}
		}
		if g.MaintenanceEnabled && !g.allowPath(p) {
			if g.MaintenanceRetry > 0 {
				ctx.Response.Header.Set("Retry-After", strconv.Itoa(g.MaintenanceRetry))
			}
			g.serveFileOrStatus(ctx, fasthttp.StatusServiceUnavailable, "public/errors/maintenance.html", "maintenance")
			return
		}
		if !g.allowPath(p) {
			if g.Store != nil && g.Store.HasCaptcha(ip) {
				if _, ok := security.ReadAndVerify(ctx, g.Secret); !ok && g.CaptchaEnabled {
					g.logAttack(ctx, ip, "captcha_flag", "captcha", 0)
					g.redirectToCaptcha(ctx, ip)
					return
				}
			}

			rateLimited := false
			if toggles.RateLimiting {
				redisOK := true
				if g.Store != nil && g.RateLimitRPS > 0 && g.RateLimitWindowMs > 0 {
					winSec := g.RateLimitWindowMs / 1000
					if winSec <= 0 {
						winSec = 1
					}
					redisOK = g.Store.AllowRateIP(rateKey, int64(g.RateLimitRPS), winSec)
				}
				inmemOK := true
				if g.Limiter != nil {
					inmemOK = g.Limiter.Allow(rateKey)
				}
				if !redisOK || !inmemOK {
					rateLimited = true
				}
			}

			if rateLimited {
				if g.bump(ip, 40, toggles, ctx) {
					return
				}
				g.logAttack(ctx, ip, "rate_limit", "rst", 0)
				if g.rst(ctx) {
					return
				}
				g.softThrottle(300)
				g.throttle(ctx)
				return
			}

			if method == "POST" && len(ctx.Request.Body()) > 512*1024 && !modernBrowser(string(ctx.UserAgent())) {
				if g.bump(ip, 90, toggles, ctx) {
					return
				}
			}

			if !hasGzipOrBr(ctx) {
				if g.bump(ip, 10, toggles, ctx) {
					return
				}
			}

			if toggles.CVAC && g.CVAC != nil {
			}

			if has("ua_referrer_blocking") && languageSuspicious(ctx) {
				if g.bump(ip, 20, toggles, ctx) {
					return
				}
				if toggles.Captcha && !g.isTrusted(ip) {
					g.logAttack(ctx, ip, "language_suspicious", "captcha", 0)
					g.softThrottle(200)
					g.redirectToCaptcha(ctx, ip)
				} else {
					g.logAttack(ctx, ip, "language_suspicious", "throttle", 0)
					g.softThrottle(200)
					if throttleOn {
						g.throttle(ctx)
						return
					}
				}
				return
			}

			if has("cookie_verification") {
				ua := string(ctx.UserAgent())
				accept := string(ctx.Request.Header.Peek("Accept"))
				if ua == "" || accept == "" {
					ttl := 2 * time.Hour
					security.SetSigned(ctx, g.Secret, security.NewPayload(ctx, "", fp, "", ttl), ctx.IsTLS())
					g.logAttack(ctx, ip, "cookie_headers_missing", "throttle", 0)
					g.softThrottle(200)
					if throttleOn {
						g.throttle(ctx)
						return
					}
					return
				}
				hasCookies := len(ctx.Request.Header.Cookie("cshield_p")) > 0 && len(ctx.Request.Header.Cookie("cshield_v")) > 0

				if hasCookies && g.signedPayloadMalformed(ctx) {
					g.logAttack(ctx, ip, "cookie_malformed", "block_502", 0)
					g.serveFileOrStatus(ctx, fasthttp.StatusBadGateway, "public/errors/502.html", "bad gateway")
					return
				}

				if !hasCookies {
					ttl := 2 * time.Hour
					security.SetSigned(ctx, g.Secret, security.NewPayload(ctx, "", fp, "", ttl), ctx.IsTLS())
				} else {
					pay, ok := security.ReadAndVerify(ctx, g.Secret)
					if !ok {
						if g.bump(ip, 50, toggles, ctx) {
							return
						}
						if toggles.CVAC && g.CVAC != nil {
							_ = g.CVAC.FailCookie(ip)
						}
						if toggles.Captcha && !g.isTrusted(ip) {
							g.logAttack(ctx, ip, "cookie_invalid", "captcha", 0)
							g.redirectToCaptcha(ctx, ip)
							return
						}
						g.logAttack(ctx, ip, "cookie_invalid", "rst", 0)
						if g.rst(ctx) {
							return
						}
						g.forbidden(ctx)
						return
					}

					if g.Replay != nil && !g.Replay.Mark(pay.SessID, pay.Nonce, pay.Exp) {
						if g.bump(ip, 30, toggles, ctx) {
							return
						}
						if toggles.CVAC && g.CVAC != nil {
							_ = g.CVAC.FailCookie(ip)
						}
						g.logAttack(ctx, ip, "cookie_replay", "rst", 0)
						if g.rst(ctx) {
							return
						}
						g.forbidden(ctx)
						return
					}

					if toggles.CVAC && g.CVAC != nil {
						if g.CVAC.FingerprintChanged(pay.SessID, pay.FP) {
							if g.Replay != nil {
								g.Replay.Reset(pay.SessID)
							}
							if g.bump(ip, 30, toggles, ctx) {
								return
							}
							if toggles.Captcha && !g.isTrusted(ip) {
								g.logAttack(ctx, ip, "fingerprint_change", "captcha", 0)
								g.redirectToCaptcha(ctx, ip)
								return
							}
							g.logAttack(ctx, ip, "fingerprint_change", "throttle", 0)
							if throttleOn {
								g.throttle(ctx)
								return
							}
							g.softThrottle(200)
							return
						} else {
							g.CVAC.ResetCookieFails(ip)
						}
					}

					ref := string(ctx.Request.Header.Peek("Referer"))
					if ref == "" || !strings.Contains(ref, "://") {
						if g.bump(ip, 20, toggles, ctx) {
							return
						}
					}

					ttl := time.Until(time.Unix(pay.Exp, 0))
					if ttl <= 0 {
						ttl = 2 * time.Hour
					}
					np := security.NewPayload(ctx, pay.SessID, pay.FP, pay.DevID, ttl)
					np.Role = pay.Role
					security.SetSigned(ctx, g.Secret, np, ctx.IsTLS())
				}
			}

			if toggles.WAF && g.WAF != nil && (has("sqli_xss_bad_payload") || has("header_uri_filtering")) {
				switch g.WAF.Inspect(ctx) {
				case waf.Block:
					_ = g.bump(ip, 80, toggles, ctx)
					g.logAttack(ctx, ip, "waf_block", "rst", 0)
					if g.rst(ctx) {
						return
					}
					g.forbidden(ctx)
					return
				case waf.Captcha:
					if g.bump(ip, 40, toggles, ctx) {
						return
					}
					if toggles.Captcha {
						g.logAttack(ctx, ip, "waf_captcha", "captcha", 0)
						g.redirectToCaptcha(ctx, ip)
						return
					}
					g.logAttack(ctx, ip, "waf_captcha", "block", 0)
					g.forbidden(ctx)
					return
				case waf.Throttle:
					if g.bump(ip, 25, toggles, ctx) {
						return
					}
					g.logAttack(ctx, ip, "waf_throttle", "throttle", 0)
					g.softThrottle(300)
					if throttleOn {
						g.throttle(ctx)
						return
					}
					return
				case waf.Allow:
				}
			}
		}

		if g.Cache != nil && method == "GET" && !g.allowPath(p) && !isBot {
			if ent, ok := g.Cache.Get(ip, p, method, fp, true); ok {
				for hk, hv := range ent.Headers {
					ctx.Response.Header.Set(hk, hv)
				}
				ctx.SetStatusCode(ent.Status)
				ctx.Response.SetBody(append([]byte(nil), ent.Body...))
				return
			}
		}

		start := time.Now()
		next(ctx)
		_ = start
		status := ctx.Response.StatusCode()
		body := ctx.Response.Body()
		if g.Cache != nil && method == "GET" && !g.allowPath(p) && !isBot && status >= 200 && status < 400 {
			hdrs := map[string]string{}
			ctx.Response.Header.VisitAll(func(k, v []byte) {
				ks := strings.ToLower(string(k))
				if ks == "set-cookie" {
					return
				}
				hdrs[string(k)] = string(v)
			})
			g.Cache.Set(ip, p, method, fp, true, status, body, hdrs)
		}
		g.Metrics.AddBytesOut(len(body))
		g.Metrics.IncStatus(status)
		if status >= 400 {
			g.Metrics.IncErrors()
		}
	}
}