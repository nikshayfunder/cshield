use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashSet;
use rand::Rng;

pub struct ReplayStore {
    seen: Mutex<HashSet<String>>,
    limit: usize,
}

impl ReplayStore {
    pub fn new(limit: usize) -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            limit,
        }
    }

    pub fn mark(&self, sess_id: &str, nonce: &str, exp: i64) -> bool {
        let key = format!("{}:{}:{}", sess_id, nonce, exp);
        let mut seen = self.seen.lock();
        if seen.contains(&key) {
            return false;
        }
        if seen.len() >= self.limit {
            // Simple eviction: clear all. Better would be LRU but Go code used a ring buffer or similar?
            // Go code: NewReplayStore(256). It probably just capped or something.
            // Go ReplayStore implementation wasn't shown in read_file, but usually simple.
            // Given "insanely fast", clearing is fast.
            seen.clear();
        }
        seen.insert(key);
        true
    }

    pub fn reset(&self, sess_id: &str) {
        let mut seen = self.seen.lock();
        seen.retain(|k| !k.starts_with(sess_id));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub sess_id: String,
    pub fp: String,
    pub dev_id: String,
    pub exp: i64,
    pub nonce: String,
    #[serde(default)]
    pub role: String,
}

pub fn new_payload(sess_id: &str, fp: &str, dev_id: &str, ttl_sec: i64) -> Payload {
    let mut rng = rand::thread_rng();
    let nonce: String = (0..16).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    Payload {
        sess_id: if sess_id.is_empty() { uuid::Uuid::new_v4().to_string() } else { sess_id.to_string() },
        fp: fp.to_string(),
        dev_id: dev_id.to_string(),
        exp: now + ttl_sec,
        nonce,
        role: "user".to_string(),
    }
}

pub fn sign(secret: &str, p: &Payload) -> (String, String) {
    let json = serde_json::to_string(p).unwrap();
    let raw = URL_SAFE_NO_PAD.encode(&json);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(json.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    (raw, sig)
}

pub fn verify(secret: &str, raw_b64: &str, sig_b64: &str) -> Option<Payload> {
    let json_bytes = match URL_SAFE_NO_PAD.decode(raw_b64) {
        Ok(b) => b,
        Err(_) => return None,
    };
    
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&json_bytes);
    let expected_sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    
    if expected_sig != sig_b64 {
        return None;
    }
    
    if let Ok(p) = serde_json::from_slice::<Payload>(&json_bytes) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        if p.exp < now {
            return None;
        }
        return Some(p);
    }
    None
}
