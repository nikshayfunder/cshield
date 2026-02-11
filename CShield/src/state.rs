use std::sync::Arc;
use crate::config::{AppConfig, LoginUser};
use crate::internal::{
    analytics::Metrics,
    cvac::Engine as CvacEngine,
    geo::Resolver,
    proxy::Manager,
    ratelimit::Limiter,
    storage::Store,
    waf::Engine as WafEngine,
    security::ReplayStore,
};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<AppConfig>>,
    pub metrics: Arc<Metrics>,
    pub geo: Arc<Resolver>,
    pub proxy_manager: Arc<Manager>,
    pub store: Arc<Store>,
    pub limiter: Arc<Limiter>,
    pub waf: Arc<WafEngine>,
    pub cvac: Arc<CvacEngine>,
    pub replay: Arc<ReplayStore>,
    pub user_coll: Option<mongodb::Collection<LoginUser>>,
    pub whitelist_ips: Arc<RwLock<Vec<String>>>,
    pub features: Arc<RwLock<crate::config::FeaturesConfig>>,
    pub maintenance_enabled: Arc<RwLock<bool>>,
    pub maintenance_msg: Arc<RwLock<String>>,
    pub maintenance_retry: Arc<RwLock<i32>>,
}
