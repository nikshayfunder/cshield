use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hyper::body::to_bytes;
use std::collections::HashMap;
use crate::state::AppState;
use crate::internal::{waf, cvac};

pub async fn middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next<Body>,
) -> Response {
    let metrics = &state.metrics;
    metrics.inc_requests();

    // CShield IP Resolution:
    // Prioritize standard X-Forwarded-For or custom header if configured.
    // Falls back to socket address (simulated here as we need ConnectInfo injection in main).
    // Note: In production, CShield edge should terminate connection, so peer_addr is the client.
    // If behind another LB, use XFF.
    
    let ip = if let Some(h) = req.headers().get("x-forwarded-for") {
        h.to_str().unwrap_or("").split(',').next().unwrap_or("").trim().to_string()
    } else if let Some(h) = req.headers().get("x-real-ip") {
        h.to_str().unwrap_or("").to_string()
    } else {
        "127.0.0.1".to_string()
    };

    metrics.record_ip(&ip);
    
    let _ = state.ip_sender.send(ip.clone());

    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    if allow_path(&path) {
        return next.run(req).await;
    }
    if is_static_path(&path) {
        return next.run(req).await;
    }

    let host = req
        .headers()
        .get("host")
        .and_then(|h: &HeaderValue| h.to_str().ok())
        .unwrap_or("");
    let host_no_port = host.split(':').next().unwrap_or(host);

    if host_no_port.parse::<std::net::IpAddr>().is_ok() {
        metrics.add_attack(crate::internal::analytics::AttackEvent {
            time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
            ip: ip.clone(),
            path: path.clone(),
            method: method.clone(),
                ua: req
                    .headers()
                    .get("user-agent")
                    .and_then(|h: &HeaderValue| h.to_str().ok())
                    .unwrap_or("")
                    .to_string(),
            reason: "direct_ip".to_string(),
            action: "block".to_string(),
            score: 0,
            status: 403,
        });
        return (StatusCode::FORBIDDEN, "Direct IP access blocked").into_response();
    }
    
    {
        let whitelist = state.whitelist_ips.read().await;
        if whitelist.contains(&ip) {
            return next.run(req).await;
        }
    }

    let proxy_features = state.proxy_manager.features_for_host(host_no_port);
    let cvac_enabled = proxy_features.as_ref().map(|f| f.cvac).unwrap_or(true);
    let waf_enabled = proxy_features.as_ref().map(|f| f.waf).unwrap_or(true);

    if cvac_enabled {
        let headers_vec: Vec<String> = req.headers().keys().map(|k| k.to_string()).collect();
        let cookie_vec: Vec<String> = req.headers().get("cookie")
            .map(|v| v.to_str().unwrap_or("").split(';').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
        let ua = req
            .headers()
            .get("user-agent")
            .and_then(|h: &HeaderValue| h.to_str().ok())
            .unwrap_or("")
            .to_string();
        
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        
        // JA4 and Cipher Suite extraction placeholers.
        // In a real Rust implementation, these come from `req.extensions().get::<TlsInfo>()`.
        // We will implement the extraction logic assuming a custom TlsInfo struct exists.
        
        let ja4 = req
            .headers()
            .get("x-ja4-fingerprint")
            .and_then(|h: &HeaderValue| h.to_str().ok())
            .map(|s: &str| s.to_string());
        // For cipher, we usually get it from the TLS terminator via header
        let cipher_suite = req
            .headers()
            .get("x-tls-cipher-id")
            .and_then(|h: &HeaderValue| h.to_str().ok())
            .and_then(|s: &str| s.parse::<u16>().ok());

        let req_info = cvac::RequestInfo {
            ip: ip.clone(),
            path: path.clone(),
            method: method.clone(),
            headers: headers_vec,
            cookies: cookie_vec,
            user_agent: ua.clone(),
            body_bytes: 0,
            is_login: path == "/login" || path == "/v1/api/login",
            now,
            asn: None, // ASN lookup should happen here via state.geo.lookup(&ip).await
            country: None,
            ja3: None, // Deprecated in favor of JA4 per instructions
            ja4,
            cipher_suite,
            http_version: format!("{:?}", req.version()),
        };
        
        let decision = state.cvac.decide(&req_info);
        
        match decision.action {
            cvac::Action::HardBlock => {
                metrics.inc_blocked();
                metrics.add_attack(crate::internal::analytics::AttackEvent {
                    time: now as i64,
                    ip: ip.clone(),
                    path: path.clone(),
                    method: method.clone(),
                    ua: ua.clone(),
                    reason: "cvac_hard_block".to_string(),
                    action: "block".to_string(),
                    score: decision.risk_score as i32,
                    status: 403,
                });
                return (StatusCode::FORBIDDEN, "Access Denied").into_response();
            },
            cvac::Action::Challenge => {
                metrics.inc_captcha();
                return axum::response::Redirect::to("/captcha.html").into_response();
            },
            cvac::Action::Tarpit(ms) => {
                metrics.inc_throttled();
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            },
            cvac::Action::SoftLimit => {
                metrics.inc_throttled();
                metrics.add_attack(crate::internal::analytics::AttackEvent {
                    time: now as i64,
                    ip: ip.clone(),
                    path: path.clone(),
                    method: method.clone(),
                    ua: ua.clone(),
                    reason: "cvac_soft_limit".to_string(),
                    action: "throttle".to_string(),
                    score: decision.risk_score as i32,
                    status: 429,
                });
                return (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests").into_response();
            },
            cvac::Action::Allow | cvac::Action::DeepInspect => {
                // Continue
            }
        }
    }

    if waf_enabled {
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body).await.unwrap_or_default();
        let body_len = bytes.len();
        
        let decision = state.waf.inspect(&parts.uri.to_string(), parts.method.as_str(), &parts.headers, body_len);
        
        // If WAF blocks, update CVAC risk
        if let waf::Decision::Block = decision {
            state.cvac.bump_ip(&ip, 50.0);
        }
        
        let req = Request::from_parts(parts, Body::from(bytes));

        match decision {
             waf::Decision::Block => {
                 metrics.inc_blocked();
                 metrics.add_attack(crate::internal::analytics::AttackEvent {
                    time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64,
                    ip: ip.clone(),
                    path: path.clone(),
                    method: method.clone(),
                    ua: req
                        .headers()
                        .get("user-agent")
                        .and_then(|h: &HeaderValue| h.to_str().ok())
                        .unwrap_or("")
                        .to_string(),
                    reason: "waf_block".to_string(),
                    action: "block".to_string(),
                    score: 0,
                    status: 403,
                });
                 return (StatusCode::FORBIDDEN, "WAF Blocked").into_response();
             },
             waf::Decision::Captcha => {
                 metrics.inc_captcha();
                 return axum::response::Redirect::to("/captcha.html").into_response();
             },
             waf::Decision::Throttle => {
                 metrics.inc_throttled();
                 tokio::time::sleep(std::time::Duration::from_millis(500)).await;
             },
             waf::Decision::Allow => {},
        }
        
        let response: Response = next.run(req).await;
        metrics.inc_status(response.status().as_u16() as i32);
        
        // Post-Response Analysis (Feedback Loop)
        // If the origin returns an error (4xx/5xx), we feed this back to CVAC to increase risk.
        // This helps detect attacks that pass WAF but fail at the application logic (e.g., auth brute force, bad inputs).
        let status = response.status().as_u16();
        if status >= 400 {
             metrics.inc_errors();
             state.cvac.bump_from_status(&ip, status);
        }
        
        return response;
    }

    let response: Response = next.run(req).await;
    metrics.inc_status(response.status().as_u16() as i32);
    
    // Post-Response Analysis (Feedback Loop)
    let status = response.status().as_u16();
    if status >= 400 {
         metrics.inc_errors();
         state.cvac.bump_from_status(&ip, status);
    }
    
    response
}

fn allow_path(p: &str) -> bool {
    if p == "/healthz" || p.starts_with("/sse/") { return true; }
    if p == "/v1/api/login" || p == "/login" || p == "/register" || p == "/dashboard" { return true; }
    if p.starts_with("/v1/api/captcha/") { return true; }
    if ["/dashboard.html", "/settings.html", "/add_proxy.html", "/proxies.html", "/dashboard", "/settings", "/add_proxy", "/proxies", "/login.html", "/register.html", "/captcha.html",
        "/analytics.html", "/analytics", "/features.html", "/features", "/actions.html", "/actions", "/users.html", "/logs.html", "/logs"].contains(&p) { return true; }
    if p.starts_with("/v1/api/") { return true; }
    if p.starts_with("/public/") { return true; }
    false
}

fn is_static_path(p: &str) -> bool {
    if let Some(idx) = p.rfind('.') {
        let ext = &p[idx+1..];
        return matches!(ext.to_lowercase().as_str(), "css" | "js" | "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "svg" | "woff" | "woff2" | "ttf" | "otf" | "map");
    }
    false
}
