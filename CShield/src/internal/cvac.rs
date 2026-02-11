use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestInfo {
    pub ip: String,
    pub path: String,
    pub method: String,
    pub headers: Vec<String>,
    pub cookies: Vec<String>,
    pub user_agent: String,
    pub body_bytes: usize,
    pub is_login: bool,
    pub now: u64,
    pub asn: Option<String>,
    pub country: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub cipher_suite: Option<u16>,
    pub http_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Action {
    Allow,
    SoftLimit,
    Challenge,
    Tarpit(u64), // delay ms
    DeepInspect,
    HardBlock,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum InspectionTier {
    FastPath,
    Scrubbing,
    DeepInspection,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObserveResult {
    pub action: Action,
    pub tier: InspectionTier,
    pub risk_score: u8,
    pub predicted_score: u8,
    pub signals: Vec<String>,
    pub fingerprint: String,
}

struct WindowCounter {
    count: u64,
    start: u64,
    duration: u64,
}

impl WindowCounter {
    fn new(duration: u64) -> Self {
        Self { count: 0, start: 0, duration }
    }
    
    fn add(&mut self, now: u64, n: u64) -> f64 {
        if self.start == 0 { self.start = now; }
        if now >= self.start + self.duration {
            // Simple reset or decay could be implemented. Here we reset for simplicity/speed
            self.count = 0;
            self.start = now;
        }
        self.count += n;
        let elapsed = now - self.start;
        if elapsed == 0 { return self.count as f64; }
        self.count as f64 / elapsed as f64
    }
}

struct IpBehavior {
    first_seen: u64,
    last_seen: u64,
    
    // Rate tracking
    rps_1s: WindowCounter,
    rps_10s: WindowCounter,
    rps_60s: WindowCounter,
    
    last_request_ts: u64,
    fast_streak: u32,
    
    login_failures: u32,
    cookie_failures: u32,
    
    fingerprints: HashSet<String>,
    
    risk_score: f64,
    
    // Route baselines (simplified as map of method:path -> count)
    routes: HashMap<String, u64>,
}

impl IpBehavior {
    fn new(now: u64) -> Self {
        Self {
            first_seen: now,
            last_seen: now,
            rps_1s: WindowCounter::new(1),
            rps_10s: WindowCounter::new(10),
            rps_60s: WindowCounter::new(60),
            last_request_ts: 0,
            fast_streak: 0,
            login_failures: 0,
            cookie_failures: 0,
            fingerprints: HashSet::new(),
            risk_score: 0.0,
            routes: HashMap::new(),
        }
    }
}

struct FingerprintState {
    seen_ips: HashSet<String>,
    last_seen: u64,
    bad_score: f64,
}

pub struct Engine {
    ips: DashMap<String, RwLock<IpBehavior>>,
    fingerprints: DashMap<String, RwLock<FingerprintState>>,
    
    // Global stats for anomaly detection (simplified)
    global_avg_rps: AtomicU64,
    
    // Config/Weights
    weights: HashMap<String, f64>,
    
    known_bot_ja3: HashSet<String>,
    known_browser_ja3: HashSet<String>,
    known_bot_ja4: HashSet<String>,
}

impl Engine {
    pub fn new() -> Self {
        let mut weights = HashMap::new();
        weights.insert("RateJump".to_string(), 10.0);
        weights.insert("ImpossibleTiming".to_string(), 15.0);
        weights.insert("CookieFailsHigh".to_string(), 20.0);
        weights.insert("FingerprintChanged".to_string(), 15.0);
        weights.insert("SharedBotFingerprint".to_string(), 25.0);
        weights.insert("HighEntropyPath".to_string(), 10.0);
        weights.insert("LoginFailSpike".to_string(), 30.0);
        weights.insert("BadASN".to_string(), 10.0);
        weights.insert("KnownBotJA3".to_string(), 50.0);
        weights.insert("KnownBotJA4".to_string(), 60.0);
        weights.insert("WeakCipher".to_string(), 20.0);
        weights.insert("HTTP10Flood".to_string(), 25.0);
        
        let mut known_bot_ja3 = HashSet::new();
        known_bot_ja3.insert("e7d705a3286e19ea42f587b344ee6865".to_string());
        known_bot_ja3.insert("6734f37431670b3ab4292b8f60f29984".to_string());
        known_bot_ja3.insert("4d7a28d6f2263ed61de88ca66eb2e89f".to_string());
        known_bot_ja3.insert("9e10692f1b7f78228b2d4e424db3a98c".to_string());
        known_bot_ja3.insert("e3bb8f76f57d4e4f1d2cc1d7d0a97b8e".to_string());
        known_bot_ja3.insert("b32309a26951912be7dba376398abc3b".to_string());
        known_bot_ja3.insert("3b5074b1b5d032e5620f69f9f700ff0e".to_string());
        known_bot_ja3.insert("a0e9f5d64349fb13191bc781f81f42e1".to_string());

        let mut known_browser_ja3 = HashSet::new();
        known_browser_ja3.insert("cd08e31494f9531f560d64c695473da9".to_string());
        known_browser_ja3.insert("b985f1ee3c3f3244e8eaf8a4f3a9e0f7".to_string());
        known_browser_ja3.insert("773906b0efdefa24a7f2b8eb6985bf37".to_string());
        known_browser_ja3.insert("394441ab65754e2207b1e1b457b3641d".to_string());
        known_browser_ja3.insert("579ccef312d18482fc42e2b822ca2430".to_string());

        // Detailed JA4 Bad Fingerprints (Simulation of common tools/bots)
        // Format: Protocol_TLSVersion_CipherHash_ExtensionsHash
        let mut known_bot_ja4 = HashSet::new();
        known_bot_ja4.insert("t13d1516h2_8daaf6152771_e3b0c44298fc".to_string()); // curl 7.68.0
        known_bot_ja4.insert("t13d1516h2_8daaf6152771_2522778d655f".to_string()); // python-requests 2.22+
        known_bot_ja4.insert("t12d4506h1_83f9c6d32836_77c7700a7479".to_string()); // Go-http-client/1.1
        known_bot_ja4.insert("t13d3605h2_2a430552763f_2723315720d2".to_string()); // Masscan TLS
        known_bot_ja4.insert("t12d1905h1_e7d705a3286e_237d825c5678".to_string()); // ZGrab2
        known_bot_ja4.insert("t13d1516h2_b32309a26951_3b5074b1b5d0".to_string()); // Shodan Scanners
        known_bot_ja4.insert("t13d1516h2_9e10692f1b7f_a0e9f5d64349".to_string()); // Censys

        Self {
            ips: DashMap::new(),
            fingerprints: DashMap::new(),
            global_avg_rps: AtomicU64::new(0),
            weights,
            known_bot_ja3,
            known_browser_ja3,
            known_bot_ja4,
        }
    }

    pub fn decide(&self, req: &RequestInfo) -> ObserveResult {
        let now = req.now;
        if now == 0 { return self.decide_with_time(req, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()); }
        self.decide_with_time(req, now)
    }

    fn decide_with_time(&self, req: &RequestInfo, now: u64) -> ObserveResult {
        let mut signals = Vec::new();
        let mut score_bump = 0.0;
        
        // 1. IP Behavior Tracking
        // Use entry to avoid multiple lookups, but we need write access
        let mut ip_entry = self.ips.entry(req.ip.clone()).or_insert_with(|| RwLock::new(IpBehavior::new(now)));
        let mut ip_state = ip_entry.write();
        
        ip_state.last_seen = now;
        
        // Rates
        let r1 = ip_state.rps_1s.add(now, 1);
        let r10 = ip_state.rps_10s.add(now, 1);
        let _ = ip_state.rps_60s.add(now, 1);
        
        // Rate Jump Signal
        // Cloudflare uses dynamic baselining. We approximate with std dev logic if we had history.
        // Here we tighten the burst threshold.
        if r1 > 35.0 {
            signals.push("HighVolRPS".to_string());
            score_bump += 15.0 + (r1 / 5.0); // Steeper penalty
        }
        if r1 > 8.0 && r1 > (r10 * 2.5) {
            signals.push("RateJump".to_string());
            score_bump += self.weights.get("RateJump").unwrap_or(&10.0);
        }

        // Impossible Timing
        // Use millisecond precision for finer granularity if available in RequestInfo.
        // Falling back to second-based burst detection.
        // 15 reqs/sec burst implies <66ms gap avg, suspicious for humans.
        if ip_state.last_request_ts == now {
            ip_state.fast_streak += 1;
            if ip_state.fast_streak > 15 {
                signals.push("ImpossibleTiming".to_string());
                score_bump += self.weights.get("ImpossibleTiming").unwrap_or(&15.0);
            }
        } else {
            ip_state.fast_streak = 0;
        }
        ip_state.last_request_ts = now;

        // Fingerprinting
        let fp = self.compute_fingerprint(req);
        if !ip_state.fingerprints.contains(&fp) {
            if !ip_state.fingerprints.is_empty() {
                signals.push("FingerprintChanged".to_string());
                score_bump += self.weights.get("FingerprintChanged").unwrap_or(&15.0);
            }
            ip_state.fingerprints.insert(fp.clone());
        }
        
        // Shared Fingerprint Check
        {
            let mut fp_entry = self.fingerprints.entry(fp.clone()).or_insert_with(|| RwLock::new(FingerprintState { seen_ips: HashSet::new(), last_seen: now, bad_score: 0.0 }));
            let mut fp_state = fp_entry.write();
            fp_state.last_seen = now;
            fp_state.seen_ips.insert(req.ip.clone());
            
            if fp_state.seen_ips.len() > 50 { // Shared across 50 IPs
                signals.push("SharedBotFingerprint".to_string());
                score_bump += self.weights.get("SharedBotFingerprint").unwrap_or(&25.0);
                // Feedback loop: increase risk for this IP because of shared FP
                fp_state.bad_score += 1.0;
            }
            if fp_state.bad_score > 100.0 {
                score_bump += 20.0; // Guilt by association
            }
        }

        // Entropy
        if self.high_entropy(&req.path) {
            signals.push("HighEntropyPath".to_string());
            score_bump += self.weights.get("HighEntropyPath").unwrap_or(&10.0);
        }

        // JA3 Checks
        if let Some(ja3) = &req.ja3 {
            if self.known_bot_ja3.contains(ja3) {
                signals.push("KnownBotJA3".to_string());
                score_bump += self.weights.get("KnownBotJA3").unwrap_or(&50.0);
            }
        }

        // JA4 Checks
        if let Some(ja4) = &req.ja4 {
            if self.known_bot_ja4.contains(ja4) {
                signals.push("KnownBotJA4".to_string());
                score_bump += self.weights.get("KnownBotJA4").unwrap_or(&60.0);
            }
        }

        // TLS Version & Cipher Mismatch
        if req.user_agent.contains("Chrome/") || req.user_agent.contains("Firefox/") {
             if let Some(cipher) = req.cipher_suite {
                 if is_weak_cipher(cipher) {
                     signals.push("ModernUADegradedTLS".to_string());
                     score_bump += 35.0;
                 }
             }
        }

        // Header Order Analysis (Cloudflare "HTTP fingerprinting")
        // Check for common bot header ordering issues vs expected browser norms.
        // Simplified: check if Host is not first or second (HTTP/1.1 requires Host, browsers usually send it early).
        // Check if "Accept" headers are missing or malformed for standard browsers.
        if !req.headers.is_empty() {
            let host_idx = req.headers.iter().position(|h| h.eq_ignore_ascii_case("host"));
            if let Some(idx) = host_idx {
                if idx > 2 {
                    signals.push("AbnormalHeaderOrder".to_string());
                    score_bump += 20.0;
                }
            }
            if req.user_agent.contains("Mozilla/") {
                if !req.headers.iter().any(|h| h.eq_ignore_ascii_case("accept")) ||
                   !req.headers.iter().any(|h| h.eq_ignore_ascii_case("accept-language")) {
                    signals.push("BrowserMissingHeaders".to_string());
                    score_bump += 30.0;
                }
            }
        }

        // Protocol Anomalies
        if req.http_version == "HTTP/1.0" && req.method == "POST" {
             signals.push("HTTP10Flood".to_string());
             score_bump += self.weights.get("HTTP10Flood").unwrap_or(&25.0);
        }

        // Weak Cipher Check
        if let Some(cipher) = req.cipher_suite {
            if is_weak_cipher(cipher) {
                signals.push("WeakCipher".to_string());
                score_bump += self.weights.get("WeakCipher").unwrap_or(&20.0);
            }
        }

        // Route Anomaly
        let route_key = format!("{}:{}", req.method, req.path);
        *ip_state.routes.entry(route_key).or_insert(0) += 1;
        // Simple anomaly: if accessing sensitive route too much
        if req.is_login || req.path.contains("admin") || req.path.contains(".env") || req.path.contains("wp-login") {
             if ip_state.routes.len() > 10 { // Reduced threshold for sensitive scan
                 signals.push("SensitiveScan".to_string());
                 score_bump += 30.0;
             }
        }

        // Apply Decay to Risk Score
        // Intelligent decay based on elapsed time and current behavior.
        // Decay factor is exponential: closer to 1.0 means slower decay.
        // If attack signals present, no decay (or negative decay).
        // If clean traffic, decay accelerates.
        
        let elapsed_sec = now.saturating_sub(ip_state.last_request_ts); // Assuming last_request_ts was updated above but we want prev
        // Note: we updated last_request_ts already. Need previous value or calculate diff before update.
        // Simplified: use fixed decay per request event, modulated by signal presence.
        
        let mut decay = 0.95;
        if !signals.is_empty() {
            decay = 1.0; // No decay if actively suspicious
        } else if ip_state.risk_score > 50.0 {
            decay = 0.98; // Slow decay if already high risk ("probation")
        }
        
        ip_state.risk_score = (ip_state.risk_score * decay) + score_bump;
        
        if ip_state.risk_score > 100.0 { ip_state.risk_score = 100.0; }
        
        let score = ip_state.risk_score as u8;
        
        // Decide Tier & Action
        let (tier, action) = self.policy_logic(score, &signals, req);
        
        ObserveResult {
            action,
            tier,
            risk_score: score,
            predicted_score: score, // Placeholder for derivative
            signals,
            fingerprint: fp,
        }
    }
    
    fn policy_logic(&self, score: u8, signals: &[String], req: &RequestInfo) -> (InspectionTier, Action) {
        let mut tier = InspectionTier::FastPath;
        let mut action = Action::Allow;
        
        // Tier Escalation
        if score > 30 || !signals.is_empty() {
            tier = InspectionTier::Scrubbing;
        }
        if score > 70 {
            tier = InspectionTier::DeepInspection;
        }
        
        // Action Selection
        if score >= 90 {
            if signals.contains(&"SharedBotFingerprint".to_string()) || signals.contains(&"KnownBotJA3".to_string()) || signals.contains(&"KnownBotJA4".to_string()) {
                action = Action::HardBlock;
            } else {
                action = Action::Challenge;
            }
        } else if score >= 60 {
            action = Action::Challenge;
        } else if score >= 40 {
            // Medium risk -> Tarpit or Soft Limit
            // Random jitter delay
            action = Action::Tarpit(500 + (score as u64 * 10));
        } else if score >= 20 {
            action = Action::SoftLimit;
        }
        
        // Specific signal overrides
        if signals.contains(&"RateJump".to_string()) {
            if action == Action::Allow { action = Action::SoftLimit; }
        }
        
        (tier, action)
    }

    fn compute_fingerprint(&self, req: &RequestInfo) -> String {
        let mut hasher = Sha256::new();
        hasher.update(req.user_agent.as_bytes());
        hasher.update(b"|");
        // Hash sorted header names
        let mut headers = req.headers.clone();
        headers.sort();
        for h in headers {
            hasher.update(h.as_bytes());
            hasher.update(b",");
        }
        hex::encode(hasher.finalize())
    }
    
    fn high_entropy(&self, s: &str) -> bool {
        if s.len() < 10 { return false; }
        let mut set = HashSet::new();
        for b in s.bytes() { set.insert(b); }
        let ratio = set.len() as f64 / s.len() as f64;
        ratio > 0.75 // Heuristic
    }
    
    // External bumps
    pub fn bump_ip(&self, ip: &str, delta: f64) {
        if let Some(mut entry) = self.ips.get_mut(ip) {
            let mut state = entry.write();
            state.risk_score += delta;
            if state.risk_score > 100.0 { state.risk_score = 100.0; }
            if state.risk_score < 0.0 { state.risk_score = 0.0; }
        }
    }

    pub fn bump_from_status(&self, ip: &str, status: u16) {
        let delta = match status {
            401 | 403 => 15.0, // Auth failure / Forbidden
            404 => 5.0,        // Scanning (lower because could be typo)
            400 => 5.0,        // Bad Request (malformed)
            500..=599 => 0.0,  // Server error (might be attack causing crash, but risky to ban)
            _ => 0.0,
        };
        if delta > 0.0 {
            self.bump_ip(ip, delta);
        }
    }
    
    pub fn fail_cookie(&self, ip: &str) {
        if let Some(mut entry) = self.ips.get_mut(ip) {
            let mut state = entry.write();
            state.cookie_failures += 1;
            state.risk_score += self.weights.get("CookieFailsHigh").unwrap_or(&20.0);
            if state.risk_score > 100.0 { state.risk_score = 100.0; }
        }
    }
    
    pub fn reset_cookie_fails(&self, ip: &str) {
        if let Some(mut entry) = self.ips.get_mut(ip) {
            entry.write().cookie_failures = 0;
        }
    }
    
    pub fn score(&self, ip: &str) -> u8 {
        if let Some(entry) = self.ips.get(ip) {
            entry.read().risk_score as u8
        } else {
            0
        }
    }
}

fn is_weak_cipher(id: u16) -> bool {
    match id {
        0x000A | 0x0013 | 0x0016 | 0x002F | 0x0033 | 0x0035 | 0x0039 | 0x003C | 0x003D => true,
        0x0001..=0x0009 => true,
        0x0060..=0x0064 => true,
        _ => false,
    }
}
