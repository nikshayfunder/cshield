package auth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cshield/internal/security"
	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/bcrypt"
)

const loginPath = "configs/login.json"

type LoginUser struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}
 
type LoginConfig struct {
	Users []LoginUser `json:"users"`
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRes struct {
	Ok bool `json:"ok"`
}

func load() (LoginConfig, error) {
	var c LoginConfig
	b, err := os.ReadFile(loginPath)
	if err != nil {
		if os.IsNotExist(err) {
			return LoginConfig{Users: []LoginUser{}}, nil
		}
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

func save(c LoginConfig) error {
	if err := os.MkdirAll(filepath.Dir(loginPath), 0755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(loginPath, b, 0644)
}

func isBcryptHash(v string) bool {
	if len(v) < 4 {
		return false
	}
	p := v[:4]
	return p == "$2a$" || p == "$2b$" || p == "$2y$"
}

func VerifyPassword(stored, pw string) bool {
	if stored == "" || pw == "" {
		return false
	}
	if isBcryptHash(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(pw)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(pw)) == 1
}

func findUser(c LoginConfig, u string) *LoginUser {
	for i := range c.Users {
		if strings.EqualFold(c.Users[i].Username, u) {
			return &c.Users[i]
		}
	}
	return nil
}

func LoginHandler(secret string) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		var req loginReq
		if json.Unmarshal(ctx.PostBody(), &req) != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}

		cfg, err := load()
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}

		username := strings.TrimSpace(req.Username)
		password := strings.TrimSpace(req.Password)

		if username != "" && password != "" {
			cfgUser := findUser(cfg, username)
			if cfgUser == nil && len(cfg.Users) == 0 {
				hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
					return
				}
				cfg.Users = append(cfg.Users, LoginUser{Username: username, PasswordHash: string(hashed)})
				if err := save(cfg); err != nil {
					ctx.SetStatusCode(fasthttp.StatusInternalServerError)
					return
				}
				cfgUser = &cfg.Users[0]
			}
			if cfgUser == nil || !VerifyPassword(cfgUser.PasswordHash, password) {
				ctx.SetStatusCode(fasthttp.StatusUnauthorized)
				return
			}
			if !isBcryptHash(cfgUser.PasswordHash) {
				if hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost); err == nil {
					cfgUser.PasswordHash = string(hashed)
					_ = save(cfg)
				}
			}
			p := security.NewPayload(ctx, "admin-"+cfgUser.Username, "", cfgUser.Username, 24*time.Hour)
			p.Role = "admin"
			security.SetSigned(ctx, secret, p, ctx.IsTLS())
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetBody([]byte(`{"ok":true}`))
			return
		}

		ctx.SetStatusCode(fasthttp.StatusBadRequest)
	}
}

func RequireAdmin(secret string, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		p, ok := security.ReadAndVerify(ctx, secret)
		if !ok || p.Role != "admin" {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}
		next(ctx)
	}
}

func ChangePassword(secret string) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		p, ok := security.ReadAndVerify(ctx, secret)
		if !ok || p.Role != "admin" {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if json.Unmarshal(ctx.PostBody(), &req) != nil || req.Username == "" || req.Password == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}
		cfg, err := load()
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		u := findUser(cfg, req.Username)
		if u == nil {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			return
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		u.PasswordHash = string(hashed)
		if err := save(cfg); err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			return
		}
		ctx.SetStatusCode(fasthttp.StatusOK)
	}
}

func EnsureAdminExists(username, password string) error {
	cfg, err := load()
	if err != nil {
		return err
	}
	if len(cfg.Users) > 0 {
		return nil
	}
	if username == "" || password == "" {
		return errors.New("missing admin bootstrap credentials")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	cfg.Users = append(cfg.Users, LoginUser{Username: username, PasswordHash: string(hashed)})
	return save(cfg)
}