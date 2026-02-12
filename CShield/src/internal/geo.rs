use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub ip: String,
    #[serde(alias = "country_name")]
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    #[serde(alias = "latitude")]
    pub lat: Option<f64>,
    #[serde(alias = "longitude")]
    pub lon: Option<f64>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub timezone: Option<String>,
}

struct CacheEntry {
    info: GeoInfo,
    fetched: Instant,
}

pub struct Resolver {
    cache: RwLock<HashMap<String, CacheEntry>>,
    client: reqwest::Client,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
        }
    }

    pub async fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(ip) {
                if entry.fetched.elapsed() < Duration::from_secs(3600) {
                    return Some(entry.info.clone());
                }
            }
        }

        let url = format!("https://ipapi.co/{}/json/", ip);
        match self.client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(info) = resp.json::<GeoInfo>().await {
                    let mut cache = self.cache.write();
                    cache.insert(ip.to_string(), CacheEntry {
                        info: info.clone(),
                        fetched: Instant::now(),
                    });
                    return Some(info);
                }
            }
            Err(_) => {}
        }
        None
    }
}
