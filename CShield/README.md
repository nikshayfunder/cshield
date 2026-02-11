# CShield (Rust Edition)

Next-generation, ultra-high-performance anti-DDoS reverse proxy and edge security node, rewritten in Rust for maximum speed and safety. CShield sits in front of your origins, terminates TLS (optional), and applies L7 security, behavioral analysis (CVAC), rate limiting, WAF, captcha, and caching before proxying to your backend.

## Key Features

-   **High Performance**: Built with **Axum**, **Tokio**, and **DashMap** for insanely fast, async, lock-free concurrency.
-   **L7 Behavioral Defense (CVAC)**: Advanced engine tracking RiskScore (0-100) per IP using signals like RateJumps, ImpossibleTiming, FingerprintChanges, and Entropy.
-   **WAF**: Regex-based Web Application Firewall scanning URL, headers, and body for SQLi, XSS, and bad payloads.
-   **Rate Limiting**: Global and per-route token bucket rate limiting.
-   **Smart Scrubbing**: Tarpit (delay), Challenge (Captcha), and Soft Limiting (429) based on real-time risk scores.
-   **Reverse Proxy**: Host-based routing with upstream TLS support.
-   **Database Backed**:
    -   **MongoDB**: Persistent storage for proxies, users, and logs.
    -   **Redis**: High-speed cache, rate limit counters, and temporary bans.
-   **Admin UI**: Modern, dark-themed dashboard with live traffic analytics, geo-maps, and system controls.

## Requirements

-   **OS**: Linux (recommended for `iptables` support), Windows/macOS (development).
-   **Database**:
    -   **Redis** (default: `127.0.0.1:6379`)
    -   **MongoDB** (default: `mongodb://127.0.0.1:27017`)
-   **Rust**: Stable toolchain (1.75+).

## Build & Run

```bash
# Build release binary
cargo build --release

# Run
cargo run --release
```

On first run, CShield will:
1.  Create necessary directories (`configs/`, `public/`).
2.  Generate default configuration files in `configs/`.
3.  Direct you to the First Setup page (`/register.html`) to create your administrator account.

## Configuration

All configurations reside in the `configs/` directory:

-   `app.json`: Server binding, database URIs, TLS settings.
-   `features.json`: Global feature toggles (WAF, CVAC, Captcha, etc.).
-   `whitelist.json`: Trusted IPs that bypass filters.
-   `waf.json`: Custom WAF rules.
-   `rate_limiting.json`: Global rate limit parameters.

## Project Structure

-   `src/main.rs`: Entry point and server initialization.
-   `src/internal/`: Core logic modules.
    -   `cvac.rs`: L7 Behavioral Engine.
    -   `core.rs`: Request Middleware (The Gate).
    -   `proxy.rs`: Proxy manager.
    -   `waf.rs`: WAF engine.
    -   `analytics.rs`: Metrics and stats.
-   `public/`: HTML/CSS/JS assets for the Admin UI.

## Authentication

CShield uses a database-backed authentication system:
-   **First Run**: Visit the root URL or `/login` to be redirected to the setup wizard.
-   **User Management**: Add/Remove administrators via the Users tab in the dashboard.
-   **Security**: Passwords are hashed using bcrypt. Sessions are signed with HMAC.

## License

Private / Proprietary.
