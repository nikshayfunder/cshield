# CShield

Next-generation anti‑DDoS reverse proxy / mini‑CDN for small Linux VPS deployments. It sits in front of your origins, terminates TLS (optional), and applies L7 security, rate limiting, WAF, captcha, and caching before proxying to your backend.

## Key components

- Edge bootstrap and routing: [`main.go`](main.go)
- Protection pipeline (all security decisions): [`internal/core/gate.go`](internal/core/gate.go)
- Reverse proxy and load balancer: [`internal/proxy/manager.go`](internal/proxy/manager.go)
- WAF engine and rules: [`internal/waf/waf.go`](internal/waf/waf.go) + [`configs/waf.json`](configs/waf.json)
- Behavioral engine (CVAC, Mongo‑backed): [`internal/cvac/engine.go`](internal/cvac/engine.go)
- Metrics and analytics: [`internal/analytics/metrics.go`](internal/analytics/metrics.go)
- Redis + Mongo storage (bans, IP events, cache): [`internal/storage/store.go`](internal/storage/store.go), [`internal/cache/cache.go`](internal/cache/cache.go)
- Local firewall / IP dropping (iptables wrapper): [`internal/cwall/cwall.go`](internal/cwall/cwall.go)
- Geo IP resolver for map and analytics: [`internal/geo/geo.go`](internal/geo/geo.go)
- Admin UI (HTML dashboard, settings, logs): [`public/`](public)

## Major features

- **L7 protection**
  - CVAC engine scores behavior per IP: rate jumps, timing anomalies, header / cookie patterns, and login abuse, stored in Mongo.
  - WAF regex rules on path + query + headers, including signatures for scanners (sqlmap, Nuclei, Censys, Shodan, etc.), SQLi, XSS, JNDI, and high‑risk payloads.
  - Global rate limiting per IP / fingerprint using a token bucket.
  - Signed cookies bound to session + fingerprint with replay detection.
  - Captcha challenge/verify integrated into the gate (served from `public/captcha.html`).
  - Direct IP access protection (requests to the edge IP instead of hostname are blocked with a dedicated error page).

- **Reverse proxy / CDN node**
  - Host‑based routing to per‑domain origins, with optional CDN mode to hide the real origin.
  - Upstream TLS support with SNI.
  - Optional internal load balancer over multiple backends with health checks.

- **Redis + Mongo storage**
  - Short‑term bans and risk scores in Redis.
  - Long‑term bans and IP activity in Mongo (`bans`, `ips` collections).
  - Proxies stored in Mongo (`proxies` collection).
  - Behavioral events / rules in Mongo via CVAC.
  - Edge‑down fallback HTML cached in Redis keyed by `server_key`.

- **Admin web UI**
  - Dashboard with live metrics (RPS, blocked, captcha, throttled, errors).
  - Live attack log table (reason, action, score, country, UA).
  - Interactive traffic map with per‑IP points, zoom/pan, and clickable detail cards (IP, location, ASN, org, timezone, last seen).
  - Config editor for JSON configs under `configs/`.
  - Proxies list and LB health view.
  - Maintenance mode toggle and bans management.

## Requirements

- OS: Linux (iptables required for CWall IP dropping).
- Arch: x86_64/amd64 (others may work).
- Go: 1.22+.
- Ports: 80 (HTTP and ACME HTTP‑01 if TLS enabled), 443 (HTTPS when TLS enabled).
- Outbound HTTP allowed for:
  - Edge IP discovery and geo (ipify + ipapi).
  - Optional peers / external services you configure.
- Redis and MongoDB reachable using the URIs configured in [`configs/app.json`](configs/app.json).

## Build and run

```bash
go mod tidy
go build -o cshield
./cshield
# or for development
go run .
```

On first run CShield:

- Ensures directories via `ensureDirs` in [`main.go`](main.go).
- Ensures default configs via `ensureDefaultConfigs` in [`main.go`](main.go).
- Migrates any legacy login bootstrap format into the current `login.json` via `ensureAdminBootstrap`.

## Configuration layout

- `configs/`
  - [`app.json`](configs/app.json) – edge server config (host, port, domain, TLS, `server_key`, maintenance, and `redis` / `mongo` connection info).
  - [`features.json`](configs/features.json) – global feature toggles used by the gate.
  - [`load_balancer.json`](configs/load_balancer.json) – optional load balancer method, targets/pools, and health check settings.
  - [`peers.json`](configs/peers.json) – optional peer configuration for smart routing / multi‑scrubbing.
  - [`waf.json`](configs/waf.json) – extra WAF regex rules appended to the built‑in signatures.
  - [`page_rules.json`](configs/page_rules.json) – reserved scaffold for future page rules.
  - [`rate_limiting.json`](configs/rate_limiting.json) – global rate limit parameters.
  - [`login.json`](configs/login.json) – admin login configuration (token + users).
  - [`trusted_users.json`](configs/trusted_users.json) – IPs that are always treated as trusted/admin.
- `public/`
  - `dashboard.html`, `settings.html`, `proxies.html`, `add_proxy.html`, `logs.html`, `login.html`, `captcha.html` – admin UI pages.
  - `errors/*.html` – 403, 404, 429, 502, 503, maintenance, direct‑IP, and edge‑down error pages.

### app.json

Example:

```json
{
  "host": "0.0.0.0",
  "port": 80,
  "domain": "panel.example.com",
  "tls": {
    "enable": false,
    "cache_dir": "acme-cache",
    "email": ""
  },
  "server_key": "512-bit-random-base64",
  "maintenance": {
    "enabled": false,
    "message": "",
    "retry_after": 0
  },
  "redis": {
    "addr": "127.0.0.1:6379",
    "password": "",
    "db": 0
  },
  "mongo": {
    "uri": "mongodb://cshield:******@127.0.0.1:27017/?tls=false",
    "database": "cshield"
  }
}
```

Notes:

- `domain` is the public hostname for the CShield admin UI and login. Only this host serves `/login`, `/dashboard`, `/settings`, etc; other hosts are proxied.
- TLS settings control the optional ACME TLS front door. When enabled, CShield will obtain certificates for `domain` and any proxy domain with `tls` set to true.
- `server_key` is used for cookies, peers, captcha, and Redis fallback keying; keep it secret and identical across peers.
- Maintenance settings are applied in the gate and are controlled via the dashboard Maintenance card.

### features.json

Core defaults look like:

```json
{
  "cvac": true,
  "cwall": true,
  "ip_dropping": true,
  "captcha": true,
  "waf": true,
  "rate_limiting": true,
  "cookie_verification": true,
  "header_uri_filtering": true,
  "ua_referrer_blocking": true,
  "sqli_xss_bad_payload": true,
  "anti_bypass_detection": true,
  "peers": true,
  "analytics": true,
  "page_rules": true,
  "load_balancer": true
}
```

These are loaded at startup and can be edited from the Settings page. They toggle WAF, CVAC, CWall/IP dropping, captcha, rate limiting, peers, and analytics globally. Individual proxies inherit these unless you change them via the API.

### load_balancer.json

Structure:

```json
{
  "method": "round_robin",
  "pools": {},
  "targets": [],
  "health": {
    "path": "/healthz",
    "timeout_ms": 2000,
    "interval_ms": 5000
  }
}
```

- `targets` can be a flat list of backends or you can use `pools` keyed by domain.
- Health checks are HTTP GETs to `health.path` with the given timeout/interval.
- If both `targets` and `pools` are empty, the built‑in load balancer is effectively disabled (proxies will just go directly to their configured origin).

### peers.json

Structure used by the current peer service:

```json
{
  "smart_routing": false,
  "multi_scrubbing": false,
  "peers": [
    {
      "id": "edge-1",
      "url": "https://edge-1.example.com",
      "region": "EU"
    }
  ]
}
```

- Leave `peers` empty if you are not running multiple cooperating edges.
- When enabled, suspicious traffic information can be scrubbed across peers for multi‑scrubbing decisions.

### login.json

Canonical format for the current login flow:

```json
{
  "token": "",
  "users": [
    {
      "username": "admin",
      "password_hash": "plain-or-hashed-password"
    }
  ]
}
```

- If `users` is empty, the first successful username/password login bootstraps the first admin and writes it into `login.json`.
- If `token` is non‑empty, `/v1/api/login` will also accept a matching token field as an alternative login method.
- The `login.html` UI uses username + password, matching the `users` array in this file.

### trusted_users.json

Structure:

```json
{
  "ips": ["1.2.3.4", "10.0.0.1"]
}
```

IPs in this list are always treated as trusted: they bypass gate scoring and can access the admin UI without authenticating.

## Proxies (Mongo‑backed)

Proxies are stored in MongoDB (`proxies` collection) using the struct defined in [`internal/proxy/manager.go`](internal/proxy/manager.go). A minimal document looks like:

```json
{
  "ip": "10.0.0.10",
  "domain": "example.com",
  "port": 8080,
  "cdn": true,
  "tls": false,
  "features": {
    "cvac": true,
    "cwall": true,
    "ip_dropping": true,
    "captcha": true,
    "waf": true,
    "rate_limiting": true,
    "extras": {
      "cookie_verification": true
    }
  }
}
```

- `/add_proxy.html` creates proxies via `POST /v1/api/proxies/add`.
- `/proxies.html` lists domains and shows origin/mode and LB upstream health.

## Bans and firewall

- Bans are persisted via [`internal/storage/store.go`](internal/storage/store.go) into Redis (`ban:{ip}` keys) and Mongo (`bans` collection).
- On startup, saved bans are replayed into [`internal/cwall/cwall.go`](internal/cwall/cwall.go) to install iptables rules.
- The dashboard “Blocked IPs” card uses:
  - `GET  /v1/api/bans/list`
  - `POST /v1/api/bans/unban`
  - `POST /v1/api/bans/clear-all`

## Analytics, metrics, and traffic map

- Metrics core: [`internal/analytics/metrics.go`](internal/analytics/metrics.go).
- SSE stream for dashboard counters: `GET /sse/metrics`.
- Snapshot JSON metrics: `GET /v1/api/metrics`.
- Attack log API: `GET /v1/api/analytics/attacks`.
- Geo traffic API feeding the map and top‑countries panel: `GET /v1/api/analytics/geo`.
- Geo resolver: [`internal/geo/geo.go`](internal/geo/geo.go) using ipapi.co, including ASN, org, and timezone.

The `dashboard.html` map:

- Polls `/v1/api/analytics/geo` every few seconds.
- Displays dots for recent IPs, sized by request volume and colored by attack count.
- Supports mouse wheel zoom and drag‑to‑pan with a dynamic SVG `viewBox`.
- Lets you click on dots to open a detail card with IP, location, ASN, org, timezone, and last seen time.

## WAF

- Engine lives in [`internal/waf/waf.go`](internal/waf/waf.go).
- Built‑in patterns cover common SQLi/XSS vectors and anomalies.
- Additional patterns from [`configs/waf.json`](configs/waf.json) are appended to the "bad" rule set.
- The gate uses WAF decisions to block, throttle, or captcha requests based on score.

## CVAC behavioral engine

- Implementation: [`internal/cvac/engine.go`](internal/cvac/engine.go).
- Stores events and rules in Mongo.
- The gate uses CVAC scores and observations to:
  - Detect rate jumps and impossible timing.
  - React to cookie failures and fingerprint changes.
  - Raise scores that can lead to bans, captcha, or throttling.

## Fallback edge‑down page

- A pre‑rendered `public/errors/edge-down.html` is cached in Redis under `server_key` using [`internal/fallback`](internal/fallback).
- The main server wrapper in [`main.go`](main.go) serves this HTML if the origin or handler panics or returns upstream gateway errors, so visitors see a clear "origin offline" status page.

## Systemd example

```ini
[Unit]
Description=CShield Edge
After=network.target

[Service]
ExecStart=/usr/local/bin/cshield
WorkingDirectory=/opt/cshield
User=root
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp cshield /usr/local/bin/cshield
sudo mkdir -p /opt/cshield
sudo cp -r configs public /opt/cshield
sudo tee /etc/systemd/system/cshield.service >/dev/null <<'EOF'
[Unit]
Description=CShield Edge
After=network.target

[Service]
ExecStart=/usr/local/bin/cshield
WorkingDirectory=/opt/cshield
User=root
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now cshield
```

## Security notes

- Keep `server_key` secret and identical across peers.
- Restrict Admin UI access via firewall/VPN or a separate fronting reverse proxy.
- Ensure Redis and Mongo are not exposed directly to the public internet.
- When performing disruptive upgrades, you can:
  - Enable maintenance from the dashboard.
  - Restart nodes.
  - Disable maintenance again once the edge is healthy.

## License

Original code is under CNethuka/C/Nethuka, you own your modified code.