use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TLSCfg {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub cache_dir: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisCfg {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub db: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoCfg {
    #[serde(default)]
    pub uri: String,
    #[serde(default)]
    pub database: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceCfg {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub retry_after: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: i32,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub tls: TLSCfg,
    #[serde(default)]
    pub server_key: String,
    #[serde(default)]
    pub redis: RedisCfg,
    #[serde(default)]
    pub mongo: MongoCfg,
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> i32 { 80 }

impl Default for TLSCfg {
    fn default() -> Self {
        Self { enable: false, cache_dir: "acme-cache".to_string(), email: "".to_string(), domain: "".to_string() }
    }
}
impl Default for RedisCfg {
    fn default() -> Self {
        Self { addr: "127.0.0.1:6379".to_string(), password: "".to_string(), db: 0 }
    }
}
impl Default for MongoCfg {
    fn default() -> Self {
        Self { uri: "mongodb://127.0.0.1:27017".to_string(), database: "cshield".to_string() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesConfig {
    #[serde(default = "default_true")]
    pub cvac: bool,
    #[serde(default = "default_true")]
    pub cwall: bool,
    #[serde(default = "default_true")]
    pub ip_dropping: bool,
    #[serde(default = "default_true")]
    pub asn_blocking: bool,
    #[serde(default = "default_true")]
    pub captcha: bool,
    #[serde(default = "default_true")]
    pub waf: bool,
    #[serde(default = "default_true")]
    pub rate_limiting: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WAFConfig {
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRulesConfig {
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    #[serde(default = "default_rps")]
    pub global_rps: i32,
    #[serde(default = "default_burst")]
    pub burst: i32,
    #[serde(default = "default_window")]
    pub window_ms: i32,
}

fn default_rps() -> i32 { 300 }
fn default_burst() -> i32 { 150 }
fn default_window() -> i32 { 1000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ASNBlockConfig {
    #[serde(default)]
    pub asns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUser {
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginConfig {
    #[serde(default)]
    pub users: Vec<LoginUser>,
}
