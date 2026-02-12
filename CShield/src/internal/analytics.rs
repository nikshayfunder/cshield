use dashmap::DashMap;
use parking_lot::RwLock;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct AttackEvent {
    pub time: i64,
    pub ip: String,
    pub path: String,
    pub method: String,
    pub ua: String,
    pub reason: String,
    pub action: String,
    pub score: i32,
    pub status: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct IPStats {
    pub requests: u64,
    pub attacks: u64,
    pub last: i64,
}

pub struct Metrics {
    requests: AtomicU64,
    proxied: AtomicU64,
    errors: AtomicU64,
    blocked: AtomicU64,
    captcha: AtomicU64,
    throttled: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    status_codes: DashMap<i32, u64>,
    attack_events: RwLock<Vec<AttackEvent>>,
    ip_stats: DashMap<String, IPStats>,
    
    // RPS tracking
    rps_counter: AtomicU64,
    last_rps: AtomicU64,
    last_tick: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            proxied: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            captcha: AtomicU64::new(0),
            throttled: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            status_codes: DashMap::new(),
            attack_events: RwLock::new(Vec::new()),
            ip_stats: DashMap::new(),
            rps_counter: AtomicU64::new(0),
            last_rps: AtomicU64::new(0),
            last_tick: AtomicU64::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
        }
    }

    pub fn inc_requests(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        
        // Simple RPS tracking
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let last = self.last_tick.load(Ordering::Relaxed);
        
        if now > last {
            // Attempt to swap. If another thread did it, we just add to the new counter.
            // This is a bit racey but fine for stats.
            // Actually, better to just let a background task tick it or do it here lazily.
            // Lazy way:
            if self.last_tick.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                let count = self.rps_counter.swap(0, Ordering::Relaxed);
                self.last_rps.store(count, Ordering::Relaxed);
            }
        }
        self.rps_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_proxied(&self) {
        self.proxied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_blocked(&self) {
        self.blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_captcha(&self) {
        self.captcha.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_throttled(&self) {
        self.throttled.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_in(&self, n: usize) {
        self.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_bytes_out(&self, n: usize) {
        self.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn inc_status(&self, code: i32) {
        *self.status_codes.entry(code).or_insert(0) += 1;
    }

    pub fn add_attack(&self, ev: AttackEvent) {
        let mut events = self.attack_events.write();
        events.push(ev);
        if events.len() > 1000 {
            events.remove(0);
        }
    }

    pub fn record_ip(&self, ip: &str) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let mut entry = self.ip_stats.entry(ip.to_string()).or_insert(IPStats {
            requests: 0,
            attacks: 0,
            last: 0,
        });
        entry.requests += 1;
        entry.last = now;
    }

    pub fn mark_attack(&self, ip: &str) {
        if let Some(mut entry) = self.ip_stats.get_mut(ip) {
            entry.attacks += 1;
        }
    }

    pub fn snapshot_json(&self) -> serde_json::Value {
        let sc: std::collections::HashMap<i32, u64> = self.status_codes.iter().map(|k| (*k.key(), *k.value())).collect();
        serde_json::json!({
            "requests": self.requests.load(Ordering::Relaxed),
            "proxied": self.proxied.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "blocked": self.blocked.load(Ordering::Relaxed),
            "captcha": self.captcha.load(Ordering::Relaxed),
            "throttled": self.throttled.load(Ordering::Relaxed),
            "bytes_in": self.bytes_in.load(Ordering::Relaxed),
            "bytes_out": self.bytes_out.load(Ordering::Relaxed),
            "status_codes": sc,
        })
    }

    pub fn attack_snapshot(&self) -> Vec<AttackEvent> {
        self.attack_events.read().clone()
    }

    pub fn ip_stats_snapshot(&self) -> std::collections::HashMap<String, IPStats> {
        self.ip_stats.iter().map(|k| (k.key().clone(), k.value().clone())).collect()
    }
}
