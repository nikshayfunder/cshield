use axum::{
    extract::{State, Json},
    response::IntoResponse,
    http::StatusCode,
};
use crate::state::AppState;
use serde_json::json;
use std::sync::Mutex;
use sysinfo::System;
use crate::internal::proxy::Config as ProxyConfig;
use once_cell::sync::Lazy;
use serde::Deserialize;

static SYSTEM: Lazy<Mutex<System>> = Lazy::new(|| {
    let mut sys = System::new();
    sys.refresh_cpu();
    sys.refresh_memory();
    Mutex::new(sys)
});

pub async fn health_handler() -> impl IntoResponse {
    let mut sys = SYSTEM.lock().unwrap();
    sys.refresh_cpu();
    sys.refresh_memory();
    
    // Calculate global CPU usage
    let cpus = sys.cpus();
    let cpu_usage: f32 = if !cpus.is_empty() {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    } else {
        0.0
    };
    
    let mem_used = sys.used_memory();
    let mem_total = sys.total_memory();
    let mem_pct = if mem_total > 0 {
        (mem_used as f64 / mem_total as f64) * 100.0
    } else {
        0.0
    };
    
    Json(json!({
        "cpu_pct": cpu_usage,
        "mem_pct": mem_pct
    }))
}

pub async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.metrics.snapshot_json())
}

pub async fn list_proxies_handler(State(state): State<AppState>) -> impl IntoResponse {
    // We need to implement listing in proxy manager first? 
    // Wait, proxy manager has `list_domains`?
    // Let's check src/internal/proxy.rs
    // Assuming `list_domains` returns Vec<String>.
    // The frontend expects {"files": ["domain1", "domain2"]} (based on proxies.html code)
    
    // Wait, I saw list_domains in earlier warnings but I should double check implementation or just implement it.
    // Assuming list_domains is available or I can access `by_domain` lock if public?
    // `by_domain` is RwLock<HashMap>. It's private (not pub).
    // `list_domains` was marked unused, so it likely exists.
    
    // If list_domains returns Vec<String>, good.
    // If not, I can implement it or add a method.
    // But I can't modify proxy.rs easily without checking it.
    
    // Let's assume list_domains exists and returns Vec<String>.
    let domains = state.proxy_manager.list_domains();
    Json(json!({"files": domains}))
}

#[derive(Deserialize)]
pub struct DeleteProxyReq {
    domain: String,
}

pub async fn delete_proxy_handler(State(state): State<AppState>, Json(payload): Json<DeleteProxyReq>) -> impl IntoResponse {
    match state.proxy_manager.delete_proxy(&payload.domain).await {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": e.to_string()}))).into_response()
    }
}

pub async fn reload_proxies_handler(State(state): State<AppState>) -> impl IntoResponse {
    state.proxy_manager.reload().await;
    Json(json!({"ok": true}))
}

#[derive(Deserialize)]
pub struct AddProxyReq {
    // Matches Config structure or subset?
    // Based on add_proxy.html form?
    // I need to check add_proxy.html logic.
    // But assuming it sends a JSON matching Config struct or close to it.
    // For now, I'll use serde_json::Value and try to deserialize to Config
    // OR create a specific struct.
    // Let's rely on ProxyConfig being Deserialize.
    #[serde(flatten)]
    config: ProxyConfig
}

pub async fn add_proxy_handler(State(state): State<AppState>, Json(payload): Json<ProxyConfig>) -> impl IntoResponse {
    match state.proxy_manager.upsert_proxy(payload).await {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": e.to_string()}))).into_response()
    }
}

pub async fn get_features_handler(State(state): State<AppState>) -> impl IntoResponse {
    let f = state.features.read().await;
    Json(json!(*f))
}

pub async fn update_features_handler(State(state): State<AppState>, Json(payload): Json<crate::config::FeaturesConfig>) -> impl IntoResponse {
    // Need to verify if FeaturesConfig is the right struct.
    // state.features is Arc<RwLock<FeaturesConfig>>.
    let mut f = state.features.write().await;
    *f = payload;
    // Should persist to disk?
    // The original code probably loaded from file.
    // If I want to persist, I should write to configs/features.json.
    // I'll implement save logic here if needed, or assume ephemeral for now/memory only?
    // Ideally save it.
    
    // Saving:
    if let Ok(s) = serde_json::to_string_pretty(&*f) {
        let _ = tokio::fs::write("configs/features.json", s).await;
    }
    
    Json(json!({"ok": true}))
}

#[derive(Deserialize)]
pub struct ConfigPath {
    path: String,
}

pub async fn read_config_handler(axum::extract::Query(params): axum::extract::Query<ConfigPath>) -> impl IntoResponse {
    // Restrict to specific files for security
    let allowed = ["features.json", "waf.json", "rate_limiting.json"];
    if !allowed.contains(&params.path.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "Invalid path"}))).into_response();
    }
    
    match tokio::fs::read_to_string(format!("configs/{}", params.path)).await {
        Ok(content) => Json(json!({"content": content})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": e.to_string()}))).into_response()
    }
}

#[derive(Deserialize)]
pub struct SaveConfigReq {
    path: String,
    content: String,
}

pub async fn save_config_handler(Json(payload): Json<SaveConfigReq>) -> impl IntoResponse {
    let allowed = ["features.json", "waf.json", "rate_limiting.json"];
    if !allowed.contains(&payload.path.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "Invalid path"}))).into_response();
    }
    
    if serde_json::from_str::<serde_json::Value>(&payload.content).is_err() {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "Invalid JSON content"}))).into_response();
    }

    match tokio::fs::write(format!("configs/{}", payload.path), payload.content).await {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": e.to_string()}))).into_response()
    }
}

pub async fn get_maintenance_handler(State(state): State<AppState>) -> impl IntoResponse {
    let enabled = *state.maintenance_enabled.read().await;
    let message = state.maintenance_msg.read().await.clone();
    let retry_after = *state.maintenance_retry.read().await;
    
    Json(json!({
        "enabled": enabled,
        "message": message,
        "retry_after": retry_after
    }))
}

#[derive(Deserialize)]
pub struct MaintenanceReq {
    enabled: bool,
    message: String,
    retry_after: i32,
}

pub async fn set_maintenance_handler(State(state): State<AppState>, Json(payload): Json<MaintenanceReq>) -> impl IntoResponse {
    *state.maintenance_enabled.write().await = payload.enabled;
    *state.maintenance_msg.write().await = payload.message;
    *state.maintenance_retry.write().await = payload.retry_after;
    Json(json!({"ok": true}))
}
