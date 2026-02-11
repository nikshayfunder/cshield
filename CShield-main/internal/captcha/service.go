package captcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"cshield/internal/security"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
)

type Service struct {
	secret     string
	challenges map[string]Challenge
	sessions   map[string]*Session
	mu         sync.RWMutex
}

type Challenge struct {
	ID     string
	SessID string
	IP     string
	UA     string
	FP     string
	DevID  string
	Ts     int64
	Exp    int64
	Ref    string
}

type Session struct {
	SessID string
	IP     string
	UA     string
	FP     string
	DevID  string
	Fail   int
	Score  int
	Exp    int64
}

type newReq struct {
	FP    string `json:"fp"`
	DevID string `json:"devID"`
	Ref   string `json:"ref"`
}

type newRes struct {
	ID     string `json:"id"`
	SessID string `json:"sessID"`
}

type verifyReq struct {
	ChallengeID string       `json:"challengeID"`
	FP          string       `json:"fp"`
	DevID       string       `json:"devID"`
	Signals     verifySignal `json:"signals"`
	Ref         string       `json:"ref"`
}

type verifySignal struct {
	Moves   int     `json:"moves"`
	Jitter  float64 `json:"jitter"`
	Focus   int     `json:"focus"`
	Ts      int64   `json:"ts"`
	ClickTs int64   `json:"clickTs"`
}

type verifyRes struct {
	Ok       bool   `json:"ok"`
	Redirect string `json:"redirect,omitempty"`
	Token    string `json:"token,omitempty"`
}

func New(secret string) *Service {
	return &Service{
		secret:     secret,
		challenges: map[string]Challenge{},
		sessions:   map[string]*Session{},
	}
}

func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

type tokenPayload struct {
	IP    string `json:"ip"`
	UA    string `json:"ua"`
	Nonce string `json:"nonce"`
	Exp   int64  `json:"exp"`
}

func signToken(secret, ip, ua, nonce string, exp int64) string {
	body, _ := json.Marshal(tokenPayload{
		IP:    ip,
		UA:    ua,
		Nonce: nonce,
		Exp:   exp,
	})
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	sig := h.Sum(nil)
	return b64u(body) + "." + b64u(sig)
}

func ValidateToken(secret, tok string, ctx *fasthttp.RequestCtx) bool {
	if tok == "" {
		return false
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		return false
	}
	body, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	if !hmac.Equal(sig, h.Sum(nil)) {
		return false
	}
	var p tokenPayload
	if json.Unmarshal(body, &p) != nil {
		return false
	}
	if p.Exp < time.Now().Unix() {
		return false
	}
	// Use normalized client IP (respecting X-Forwarded-For / CF-Connecting-IP)
	// so captcha tokens remain valid behind proxies and load balancers.
	ip := security.ClientIP(ctx)
	ua := string(ctx.UserAgent())
	if p.IP != ip || p.UA != ua {
		return false
	}
	return true
}

func jsonReply(ctx *fasthttp.RequestCtx, code int, v any) {
	ctx.Response.Header.Set("Content-Type", "application/json")
	b, _ := json.Marshal(v)
	ctx.SetStatusCode(code)
	ctx.SetBody(b)
}

func (s *Service) NewChallengeHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		var req newReq
		_ = json.Unmarshal(ctx.PostBody(), &req)
		// Normalize IP the same way the rest of the firewall does.
		ip := security.ClientIP(ctx)
		ua := string(ctx.UserAgent())
		id := uuid.NewString()
		sid := uuid.NewString()
		now := time.Now().Unix()
		ch := Challenge{
			ID:     id,
			SessID: sid,
			IP:     ip,
			UA:     ua,
			FP:     req.FP,
			DevID:  req.DevID,
			Ts:     now,
			Exp:    now + 180,
			Ref:    req.Ref,
		}
		s.mu.Lock()
		s.challenges[id] = ch
		s.sessions[sid] = &Session{
			SessID: sid,
			IP:     ip,
			UA:     ua,
			FP:     req.FP,
			DevID: req.DevID,
			Fail:  0,
			Score: 0,
			Exp:   now + 86400,
		}
		s.mu.Unlock()
		jsonReply(ctx, fasthttp.StatusOK, newRes{ID: id, SessID: sid})
	}
}

func (s *Service) VerifyHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		var req verifyReq
		if json.Unmarshal(ctx.PostBody(), &req) != nil {
			jsonReply(ctx, fasthttp.StatusBadRequest, verifyRes{Ok: false})
			return
		}
		// Match IP derivation with NewChallengeHandler and the rest of the gate.
		ip := security.ClientIP(ctx)
		ua := string(ctx.UserAgent())
		lang := ctx.Request.Header.Peek("Accept-Language")

		s.mu.RLock()
		ch, ok := s.challenges[req.ChallengeID]
		s.mu.RUnlock()

		now := time.Now()
		if !ok || ch.Exp < now.Unix() {
			jsonReply(ctx, fasthttp.StatusUnauthorized, verifyRes{Ok: false})
			return
		}
		if ch.IP != ip || ch.UA != ua {
			jsonReply(ctx, fasthttp.StatusUnauthorized, verifyRes{Ok: false})
			return
		}
		if ch.FP != req.FP || ch.DevID != req.DevID {
			jsonReply(ctx, fasthttp.StatusUnauthorized, verifyRes{Ok: false})
			return
		}

		score := 0
		if req.Signals.Moves < 5 {
			score += 20
		}
		if req.Signals.Jitter < 10 {
			score += 15
		}
		if req.Signals.Focus < 1 {
			score += 10
		}
		if len(lang) == 0 {
			score += 15
		}
		if req.Ref != "" && req.Ref != ch.Ref {
			score += 10
		}

		s.mu.Lock()
		ss := s.sessions[ch.SessID]
		if ss != nil {
			ss.Score += score
			if score >= 60 {
				ss.Fail++
			}
		}
		delete(s.challenges, req.ChallengeID)
		failCount := 0
		if ss != nil {
			failCount = ss.Fail
		}
		s.mu.Unlock()

		if score >= 60 || failCount >= 5 {
			jsonReply(ctx, fasthttp.StatusForbidden, verifyRes{Ok: false})
			return
		}

		ttl := 2 * time.Hour
		payload := security.NewPayload(ctx, ch.SessID, ch.FP, ch.DevID, ttl)
		security.SetSigned(ctx, s.secret, payload, ctx.IsTLS())

		ref := ch.Ref
		if ref == "" {
			ref = "/"
		}
		expTs := now.Add(5 * time.Minute).Unix()
		tok := signToken(s.secret, ch.IP, ch.UA, ch.ID, expTs)
		jsonReply(ctx, fasthttp.StatusOK, verifyRes{Ok: true, Redirect: ref, Token: tok})
	}
}