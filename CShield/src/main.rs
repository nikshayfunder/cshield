mod config;
mod internal;
mod state;

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use internal::{
    analytics::Metrics,
    auth,
    captcha::Service as CaptchaService,
    core,
    cvac::Engine as CvacEngine,
    geo::Resolver,
    proxy::Manager,
    ratelimit::Limiter,
    security::ReplayStore,
    storage::Store,
    waf::Engine as WafEngine,
};
use config::{AppConfig, FeaturesConfig, RateLimitingConfig, TLSCfg, RedisCfg, MongoCfg};
use state::AppState;

const DIR_CONFIGS: &str = "configs";
const DIR_PUBLIC: &str = "public";
const DIR_ERRORS: &str = "public/errors";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    ensure_dirs().await?;
    ensure_default_configs().await?;

    let app_config = load_app_config().await?;
    let features_config = load_features_config().await?;
    let rl_config = load_rl_config().await?;

    let metrics = Arc::new(Metrics::new());
    let geo = Arc::new(Resolver::new());
    let store = Arc::new(Store::new(
        &app_config.redis.addr, 
        &app_config.redis.password, 
        app_config.redis.db,
        &app_config.mongo.uri, 
        &app_config.mongo.database
    ).await?);
    
    let proxy_manager = Arc::new(Manager::new(&app_config.mongo.uri, &app_config.mongo.database).await);
    
    let limiter = Arc::new(Limiter::new(rl_config.global_rps, rl_config.burst, rl_config.window_ms));
    
    let waf_rules = load_waf_rules().await?;
    let waf = Arc::new(WafEngine::new(&waf_rules));
    
    let cvac = Arc::new(CvacEngine::new());
    
    let replay = Arc::new(ReplayStore::new(256));
    
    let captcha_service = Arc::new(CaptchaService::new(app_config.server_key.clone()));
    
    let whitelist_ips = load_whitelist().await?;
    
    let mongo_client_opt = if !app_config.mongo.uri.is_empty() {
        if let Ok(opts) = mongodb::options::ClientOptions::parse(&app_config.mongo.uri).await {
            mongodb::Client::with_options(opts).ok()
        } else { None }
    } else { None };
    
    let user_coll = if let Some(client) = &mongo_client_opt {
        Some(client.database(&app_config.mongo.database).collection::<config::LoginUser>("users"))
    } else { None };

    let state = AppState {
        config: Arc::new(RwLock::new(app_config.clone())),
        metrics: metrics.clone(),
        geo: geo.clone(),
        proxy_manager: proxy_manager.clone(),
        store: store.clone(),
        limiter: limiter.clone(),
        waf: waf.clone(),
        cvac: cvac.clone(),
        replay: replay.clone(),
        user_coll,
        whitelist_ips: Arc::new(RwLock::new(whitelist_ips)),
        features: Arc::new(RwLock::new(features_config.clone())),
        maintenance_enabled: Arc::new(RwLock::new(false)),
        maintenance_msg: Arc::new(RwLock::new("".to_string())),
        maintenance_retry: Arc::new(RwLock::new(0)),
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/api/login", post(auth::login_handler))
        .route("/v1/api/register", post(auth::register_handler))
        .route("/v1/api/setup_status", get(auth::setup_status_handler))
        .route("/v1/api/users/list", get(auth::list_users_handler).layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_admin)))
        .route("/v1/api/users/delete", post(auth::delete_user_handler).layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_admin)))
        .route("/v1/api/actions/flush_ips", post(flush_ips_handler).layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_admin)))
        .route("/*path", any(proxy_handler))
        .layer(axum::middleware::from_fn_with_state(state.clone(), core::middleware))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], app_config.port as u16));
    println!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn flush_ips_handler(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(_) = state.store.clear_all_resets().await {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to clear IPs").into_response();
    }
    (StatusCode::OK, "Flushed").into_response()
}

async fn proxy_handler(State(state): State<AppState>, req: Request<Body>) -> Response {
    let host = req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
    let host_no_port = host.split(':').next().unwrap_or(host);
    
    let config = state.proxy_manager.resolve(host_no_port);
    
    if let Some(cfg) = config {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(cfg.insecure_tls.unwrap_or(true))
            .build()
            .unwrap();
            
        let scheme = if cfg.tls { "https" } else { "http" };
        let uri = req.uri();
        let path = uri.path();
        let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let url = format!("{}://{}:{}{}{}", scheme, cfg.ip, cfg.port, path, query);
        
        let method = req.method().clone();
        let headers = req.headers().clone();
        
        let body_bytes = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap_or_default();

        let mut rb = client.request(method, &url);
        for (k, v) in headers.iter() {
            if k != "host" && k != "content-length" {
                 rb = rb.header(k, v);
            }
        }
        rb = rb.header("host", &cfg.domain);
        rb = rb.body(body_bytes);

        match rb.send().await {
            Ok(resp) => {
                let status = resp.status();
                let mut builder = Response::builder().status(status);
                for (k, v) in resp.headers().iter() {
                    builder = builder.header(k, v);
                }
                let bytes = resp.bytes().await.unwrap_or_default();
                builder.body(Body::from(bytes)).unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
            Err(_) => StatusCode::BAD_GATEWAY.into_response()
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn ensure_dirs() -> anyhow::Result<()> {
    tokio::fs::create_dir_all(DIR_CONFIGS).await?;
    tokio::fs::create_dir_all(DIR_PUBLIC).await?;
    tokio::fs::create_dir_all(DIR_ERRORS).await?;
    Ok(())
}

async fn ensure_default_configs() -> anyhow::Result<()> {
    let app_path = format!("{}/app.json", DIR_CONFIGS);
    if tokio::fs::metadata(&app_path).await.is_err() {
        let default_app = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 80,
            domain: "".to_string(),
            tls: TLSCfg { enable: false, cache_dir: "acme-cache".to_string(), email: "".to_string(), domain: "".to_string() },
            server_key: uuid::Uuid::new_v4().to_string(),
            redis: RedisCfg { addr: "127.0.0.1:6379".to_string(), password: "".to_string(), db: 0 },
            mongo: MongoCfg { uri: "mongodb://127.0.0.1:27017".to_string(), database: "cshield".to_string() },
        };
        let json = serde_json::to_string_pretty(&default_app)?;
        tokio::fs::write(&app_path, json).await?;
    }
    let feat_path = format!("{}/features.json", DIR_CONFIGS);
    if tokio::fs::metadata(&feat_path).await.is_err() {
        let default_feat = FeaturesConfig {
            cvac: true, cwall: true, ip_dropping: true, asn_blocking: true, captcha: true, waf: true, rate_limiting: true,
        };
        let json = serde_json::to_string_pretty(&default_feat)?;
        tokio::fs::write(&feat_path, json).await?;
    }
    let rl_path = format!("{}/rate_limiting.json", DIR_CONFIGS);
    if tokio::fs::metadata(&rl_path).await.is_err() {
        let default_rl = RateLimitingConfig { global_rps: 300, burst: 150, window_ms: 1000 };
        let json = serde_json::to_string_pretty(&default_rl)?;
        tokio::fs::write(&rl_path, json).await?;
    }
    let waf_path = format!("{}/waf.json", DIR_CONFIGS);
    if tokio::fs::metadata(&waf_path).await.is_err() {
        let default_waf = config::WAFConfig { rules: vec![] };
        let json = serde_json::to_string_pretty(&default_waf)?;
        tokio::fs::write(&waf_path, json).await?;
    }
    let whitelist_path = format!("{}/whitelist.json", DIR_CONFIGS);
    if tokio::fs::metadata(&whitelist_path).await.is_err() {
        let default_whitelist = config::WhitelistConfig { ips: vec![] };
        let json = serde_json::to_string_pretty(&default_whitelist)?;
        tokio::fs::write(&whitelist_path, json).await?;
    }
    // No login.json default needed if using Mongo, but keeping it won't hurt if we want fallback or if auth.rs supports it.
    // User said "Instead of using login.json we use for register". So I can skip creating it or ignore it.
    Ok(())
}

async fn load_app_config() -> anyhow::Result<AppConfig> {
    let path = format!("{}/app.json", DIR_CONFIGS);
    let content = tokio::fs::read_to_string(&path).await?;
    let config: AppConfig = serde_json::from_str(&content)?;
    Ok(config)
}

async fn load_features_config() -> anyhow::Result<FeaturesConfig> {
    let path = format!("{}/features.json", DIR_CONFIGS);
    let content = tokio::fs::read_to_string(&path).await?;
    let config: FeaturesConfig = serde_json::from_str(&content)?;
    Ok(config)
}

async fn load_rl_config() -> anyhow::Result<RateLimitingConfig> {
    let path = format!("{}/rate_limiting.json", DIR_CONFIGS);
    let content = tokio::fs::read_to_string(&path).await?;
    let config: RateLimitingConfig = serde_json::from_str(&content)?;
    Ok(config)
}

async fn load_waf_rules() -> anyhow::Result<Vec<String>> {
    let path = format!("{}/waf.json", DIR_CONFIGS);
    if let Ok(content) = tokio::fs::read_to_string(&path).await {
         if let Ok(cfg) = serde_json::from_str::<config::WAFConfig>(&content) {
             return Ok(cfg.rules);
         }
    }
    Ok(vec![])
}

async fn load_whitelist() -> anyhow::Result<Vec<String>> {
    let path = format!("{}/whitelist.json", DIR_CONFIGS);
    if let Ok(content) = tokio::fs::read_to_string(&path).await {
         if let Ok(cfg) = serde_json::from_str::<config::WhitelistConfig>(&content) {
             return Ok(cfg.ips);
         }
    }
    Ok(vec![])
}

async fn load_login_users() -> anyhow::Result<Vec<config::LoginUser>> {
    // Deprecated, returning empty
    Ok(vec![])
}
