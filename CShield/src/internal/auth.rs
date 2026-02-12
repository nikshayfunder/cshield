use axum::{
    extract::State,
    http::{Request, StatusCode, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use hyper::body::to_bytes;
use serde::{Deserialize, Serialize};
use crate::internal::security;
use crate::config::LoginUser;
use crate::state::AppState;
use futures::stream::StreamExt;
use mongodb::bson::doc;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
    confirm: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    username: String,
}

pub async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    if let Some(coll) = &state.user_coll {
        if let Ok(Some(user)) = coll.find_one(doc! { "username": &payload.username }, None).await {
            if verify_hash(&payload.password, &user.password_hash) {
                let p = security::new_payload("", "", "", 86400);
                let (raw, sig) = security::sign(&state.config.read().await.server_key, &p);
                
                let mut headers = HeaderMap::new();
                headers.append("Set-Cookie", format!("cshield_p={}; Path=/; HttpOnly; SameSite=Lax", raw).parse().unwrap());
                headers.append("Set-Cookie", format!("cshield_v={}; Path=/; HttpOnly; SameSite=Lax", sig).parse().unwrap());
                return (StatusCode::OK, headers, Json(serde_json::json!({"ok": true})));
            }
        }
    }
    (StatusCode::UNAUTHORIZED, HeaderMap::new(), Json(serde_json::json!({"ok": false, "error": "invalid credentials"})))
}

pub async fn setup_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut setup = false;
    if let Some(coll) = &state.user_coll {
        if let Ok(count) = coll.count_documents(None, None).await {
            setup = count > 0;
        }
    }
    Json(serde_json::json!({"setup": setup}))
}

pub async fn login_page_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut has_users = false;
    if let Some(coll) = &state.user_coll {
        if let Ok(count) = coll.count_documents(None, None).await {
            has_users = count > 0;
        }
    }
    if has_users {
        axum::response::Redirect::to("/login.html")
    } else {
        axum::response::Redirect::to("/register")
    }
}

pub async fn register_page_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut has_users = false;
    if let Some(coll) = &state.user_coll {
        if let Ok(count) = coll.count_documents(None, None).await {
            has_users = count > 0;
        }
    }
    if has_users {
        axum::response::Redirect::to("/login")
    } else {
        axum::response::Redirect::to("/register.html")
    }
}

pub async fn dashboard_page_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cookie_header = headers
        .get("cookie")
        .and_then(|h: &HeaderValue| h.to_str().ok())
        .unwrap_or("");

    let mut p_val = "";
    let mut v_val = "";
    for cookie in cookie_header.split(';') {
        let part = cookie.trim();
        if part.starts_with("cshield_p=") {
            p_val = &part[10..];
        } else if part.starts_with("cshield_v=") {
            v_val = &part[10..];
        }
    }

    if !p_val.is_empty() && !v_val.is_empty() {
        let secret = state.config.read().await.server_key.clone();
        if let Some(payload) = security::verify(&secret, p_val, v_val) {
            if payload.role == "admin" || payload.role == "user" {
                return axum::response::Redirect::to("/dashboard.html");
            }
        }
    }

    axum::response::Redirect::to("/login")
}

pub async fn register_handler(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body).await.unwrap_or_default();
    let payload: RegisterRequest = match serde_json::from_slice(&bytes) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response(),
    };

    if payload.password != payload.confirm {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false, "error": "passwords do not match"}))).into_response();
    }

    // Check if setup allowed (count == 0) or if user is admin
    let mut allowed = false;
    let mut db_err = None;

    if let Some(coll) = &state.user_coll {
        match coll.count_documents(None, None).await {
            Ok(count) => {
                if count == 0 {
                    allowed = true;
                } else {
                    // Check cookie manually since middleware isn't applied here?
                    // Or this endpoint is protected? 
                    // The requirements say "The database will detect you have no accounts... so it will pull up a register page... After that, it will never ask again".
                    // But "Also make users.html where you can add or remove users".
                    // So register endpoint should be open for setup, but protected otherwise?
                    // I'll check auth cookie here.
                    let headers = parts.headers;
                    let cookie_header = headers
                        .get("cookie")
                        .and_then(|h: &HeaderValue| h.to_str().ok())
                        .unwrap_or("");
                    let mut p_val = "";
                    let mut v_val = "";
                    for cookie in cookie_header.split(';') {
                        let part = cookie.trim();
                        if part.starts_with("cshield_p=") { p_val = &part[10..]; }
                        else if part.starts_with("cshield_v=") { v_val = &part[10..]; }
                    }
                    if !p_val.is_empty() && !v_val.is_empty() {
                        let secret = state.config.read().await.server_key.clone();
                        if let Some(pl) = security::verify(&secret, p_val, v_val) {
                            if pl.role == "admin" || pl.role == "user" {
                                allowed = true;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                db_err = Some(e.to_string());
            }
        }
    } else {
        db_err = Some("Database not configured".to_string());
    }

    if let Some(e) = db_err {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"ok": false, "error": format!("Database error: {}", e)}))).into_response();
    }

    if !allowed {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"ok": false, "error": "setup already completed"}))).into_response();
    }

    if let Some(coll) = &state.user_coll {
        // Hash password
        let hash = match hash_password(&payload.password) {
            Ok(h) => h,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Hashing failed").into_response(),
        };
        
        let user = LoginUser {
            username: payload.username,
            password_hash: hash,
        };
        
        if let Err(_) = coll.insert_one(user, None).await {
             return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"ok": false, "error": "db error"}))).into_response();
        }
        
        return (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response();
    }

    (StatusCode::SERVICE_UNAVAILABLE, "DB unavailable").into_response()
}

pub async fn list_users_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut users = Vec::new();
    if let Some(coll) = &state.user_coll {
        if let Ok(mut cursor) = coll.find(None, None).await {
            while let Some(res) = cursor.next().await {
                if let Ok(u) = res {
                    users.push(UserInfo { username: u.username });
                }
            }
        }
    }
    Json(serde_json::json!({"users": users}))
}

pub async fn delete_user_handler(State(state): State<AppState>, Json(payload): Json<UserInfo>) -> impl IntoResponse {
    if let Some(coll) = &state.user_coll {
        if let Ok(_) = coll.delete_one(doc! { "username": payload.username }, None).await {
            return (StatusCode::OK, Json(serde_json::json!({"ok": true})));
        }
    }
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"ok": false})))
}

fn hash_password(p: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(p, bcrypt::DEFAULT_COST)
}

fn verify_hash(p: &str, h: &str) -> bool {
    bcrypt::verify(p, h).unwrap_or(false)
}

pub async fn require_admin(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: axum::middleware::Next<axum::body::Body>,
) -> Response {
    let headers = req.headers();
    let cookie_header = headers
        .get("cookie")
        .and_then(|h: &HeaderValue| h.to_str().ok())
        .unwrap_or("");
    
    let mut p_val = "";
    let mut v_val = "";
    
    for cookie in cookie_header.split(';') {
        let part = cookie.trim();
        if part.starts_with("cshield_p=") {
            p_val = &part[10..];
        } else if part.starts_with("cshield_v=") {
            v_val = &part[10..];
        }
    }

    if !p_val.is_empty() && !v_val.is_empty() {
        let secret = state.config.read().await.server_key.clone();
        if let Some(payload) = security::verify(&secret, p_val, v_val) {
            if payload.role == "admin" || payload.role == "user" {
                 return next.run(req).await;
            }
        }
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}
