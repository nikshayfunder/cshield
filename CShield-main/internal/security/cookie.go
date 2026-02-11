package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

type CookiePayload struct {
	Ts     int64  `json:"ts"`
	Exp    int64  `json:"exp"`
	IP     string `json:"ip"`
	UA     string `json:"ua"`
	FP     string `json:"fp"`
	DevID  string `json:"devID"`
	SessID string `json:"sessID"`
	Nonce  string `json:"nonce"`
	Rand   string `json:"rand"`
	Role   string `json:"role"`
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 10 {
			return true
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return true
		}
		if v4[0] == 192 && v4[1] == 168 {
			return true
		}
		if v4[0] == 127 {
			return true
		}
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if strings.HasPrefix(ip.String(), "fc") || strings.HasPrefix(ip.String(), "fd") || strings.HasPrefix(ip.String(), "fe80:") {
		return true
	}
	return false
}

func ClientIP(ctx *fasthttp.RequestCtx) string {
	remote := ctx.RemoteIP()
	ip := remote.String()

	if isPrivateIP(remote) {
		try := strings.TrimSpace(string(ctx.Request.Header.Peek("CF-Connecting-IP")))
		if try == "" {
			xff := strings.TrimSpace(string(ctx.Request.Header.Peek("X-Forwarded-For")))
			if xff != "" {
				if i := strings.Index(xff, ","); i > 0 {
					try = strings.TrimSpace(xff[:i])
				} else {
					try = xff
				}
			}
		}
		if try == "" {
			try = strings.TrimSpace(string(ctx.Request.Header.Peek("X-Real-IP")))
		}
		if try != "" {
			if tip := net.ParseIP(try); tip != nil {
				ip = tip.String()
			}
		}
	}

	return ip
}

func rb(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func sign(secret string, payload []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(payload)
	return b64(m.Sum(nil))
}

func NewPayload(ctx *fasthttp.RequestCtx, sessID, fp, devID string, ttl time.Duration) CookiePayload {
	ts := time.Now().Unix()
	exp := ts + int64(ttl.Seconds())
	if sessID == "" {
		sessID = "anon-" + b64(rb(12))
	}
	return CookiePayload{
		Ts:     ts,
		Exp:    exp,
		IP:     ClientIP(ctx),
		UA:     string(ctx.UserAgent()),
		FP:     fp,
		DevID:  devID,
		SessID: sessID,
		Nonce:  b64(rb(16)),
		Rand:   b64(rb(16)),
		Role:   "",
	}
}

func EncodePayload(p CookiePayload) (string, []byte) {
	b, _ := json.Marshal(p)
	return b64(b), b
}

func SetSigned(ctx *fasthttp.RequestCtx, secret string, p CookiePayload, secure bool) {
	pb64, raw := EncodePayload(p)
	sig := sign(secret, raw)
	pc := fasthttp.Cookie{}
	pc.SetKey("cshield_p")
	pc.SetValue(pb64)
	pc.SetPath("/")
	pc.SetHTTPOnly(true)
	pc.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	pc.SetExpire(time.Unix(p.Exp, 0))
	if secure {
		pc.SetSecure(true)
	}
	vc := fasthttp.Cookie{}
	vc.SetKey("cshield_v")
	vc.SetValue(sig)
	vc.SetPath("/")
	vc.SetHTTPOnly(true)
	vc.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	vc.SetExpire(time.Unix(p.Exp, 0))
	if secure {
		vc.SetSecure(true)
	}
	ctx.Response.Header.SetCookie(&pc)
	ctx.Response.Header.SetCookie(&vc)
}

func ReadAndVerify(ctx *fasthttp.RequestCtx, secret string) (CookiePayload, bool) {
	var p CookiePayload
	pb := ctx.Request.Header.Cookie("cshield_p")
	vb := ctx.Request.Header.Cookie("cshield_v")
	if len(pb) == 0 || len(vb) == 0 {
		return p, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(pb))
	if err != nil {
		return p, false
	}
	if sign(secret, raw) != string(vb) {
		return p, false
	}
	if json.Unmarshal(raw, &p) != nil {
		return p, false
	}
	if p.Exp < time.Now().Unix() {
		return p, false
	}
	return p, true
}