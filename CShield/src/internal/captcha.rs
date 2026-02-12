use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Clone)]
pub struct Challenge {
    pub id: String,
    pub sess_id: String,
    pub ip: String,
    pub ua: String,
    pub fp: String,
    pub dev_id: String,
    pub ts: i64,
    pub exp: i64,
    pub ref_: String,
}

#[derive(Clone)]
pub struct Session {
    pub sess_id: String,
    pub ip: String,
    pub ua: String,
    pub fp: String,
    pub dev_id: String,
    pub fail: i32,
    pub score: i32,
    pub exp: i64,
}

#[derive(Deserialize)]
pub struct NewReq {
    pub fp: String,
    #[serde(alias = "devID")]
    pub dev_id: String,
    pub ref_: String,
}

#[derive(Serialize)]
pub struct NewRes {
    pub id: String,
    #[serde(rename = "sessID")]
    pub sess_id: String,
}

#[derive(Deserialize)]
pub struct VerifyReq {
    #[serde(alias = "challengeID")]
    pub challenge_id: String,
    pub fp: String,
    #[serde(alias = "devID")]
    pub dev_id: String,
    pub signals: VerifySignal,
    pub ref_: String,
}

#[derive(Deserialize)]
pub struct VerifySignal {
    pub moves: i32,
    pub jitter: f64,
    pub focus: i32,
    pub ts: i64,
    #[serde(alias = "clickTs")]
    pub click_ts: i64,
}

#[derive(Serialize)]
pub struct VerifyRes {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TokenPayload {
    pub ip: String,
    pub ua: String,
    pub nonce: String,
    pub exp: i64,
}

pub struct Service {
    secret: String,
    challenges: RwLock<HashMap<String, Challenge>>,
    sessions: RwLock<HashMap<String, Session>>,
}

impl Service {
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            challenges: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn new_challenge(&self, ip: &str, ua: &str, req: NewReq) -> NewRes {
        let id = Uuid::new_v4().to_string();
        let sid = Uuid::new_v4().to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        
        let ch = Challenge {
            id: id.clone(),
            sess_id: sid.clone(),
            ip: ip.to_string(),
            ua: ua.to_string(),
            fp: req.fp.clone(),
            dev_id: req.dev_id.clone(),
            ts: now,
            exp: now + 180,
            ref_: req.ref_,
        };
        
        let mut challenges = self.challenges.write();
        let mut sessions = self.sessions.write();
        
        challenges.insert(id.clone(), ch);
        sessions.insert(sid.clone(), Session {
            sess_id: sid.clone(),
            ip: ip.to_string(),
            ua: ua.to_string(),
            fp: req.fp,
            dev_id: req.dev_id,
            fail: 0,
            score: 0,
            exp: now + 86400,
        });
        
        NewRes { id, sess_id: sid }
    }

    pub fn verify(&self, ip: &str, ua: &str, lang: Option<&str>, req: VerifyReq) -> (VerifyRes, Option<crate::internal::security::Payload>) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        
        let ch = {
            let challenges = self.challenges.read();
            if let Some(c) = challenges.get(&req.challenge_id) {
                c.clone()
            } else {
                return (VerifyRes { ok: false, redirect: None, token: None }, None);
            }
        };

        if ch.exp < now || ch.ip != ip || ch.ua != ua || ch.fp != req.fp || ch.dev_id != req.dev_id {
            return (VerifyRes { ok: false, redirect: None, token: None }, None);
        }

        let mut score = 0;
        if req.signals.moves < 5 { score += 20; }
        if req.signals.jitter < 10.0 { score += 15; }
        if req.signals.focus < 1 { score += 10; }
        if lang.unwrap_or("").is_empty() { score += 15; }
        if !req.ref_.is_empty() && req.ref_ != ch.ref_ { score += 10; }

        {
            let mut challenges = self.challenges.write();
            challenges.remove(&req.challenge_id);
        }
        
        let mut fail_count = 0;
        {
            let mut sessions = self.sessions.write();
            if let Some(ss) = sessions.get_mut(&ch.sess_id) {
                ss.score += score;
                if score >= 60 {
                    ss.fail += 1;
                }
                fail_count = ss.fail;
            }
        }

        if score >= 60 || fail_count >= 5 {
             return (VerifyRes { ok: false, redirect: None, token: None }, None);
        }
        
        // Return success even if failed? No, if fail_count >= 5 return false.
        // Wait, logic in previous block:
        // if score >= 60 || fail_count >= 5 { return false }
        
        // Need to construct payload
        // payload needs dev_id from challenge
        
        let ttl = 7200; // 2 hours
        let payload = crate::internal::security::new_payload(&ch.sess_id, &ch.fp, &ch.dev_id, ttl); // ch is cloned, so safe.
        
        let ref_ = if ch.ref_.is_empty() { "/".to_string() } else { ch.ref_.clone() };
        let exp_ts = now + 300;
        let tok = sign_token(&self.secret, &ch.ip, &ch.ua, &ch.id, exp_ts);

        (VerifyRes { ok: true, redirect: Some(ref_), token: Some(tok) }, Some(payload))
    }
    
    pub fn validate_token(&self, tok: &str, ip: &str, ua: &str) -> bool {
        if tok.is_empty() { return false; }
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 2 { return false; }
        
        let body_bytes = match URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(b) => b,
            Err(_) => return false,
        };
        
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).unwrap();
        mac.update(&body_bytes);
        if mac.finalize().into_bytes().as_slice() != sig.as_slice() {
            return false;
        }
        
        if let Ok(p) = serde_json::from_slice::<TokenPayload>(&body_bytes) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            if p.exp < now { return false; }
            if p.ip != ip || p.ua != ua { return false; }
            return true;
        }
        false
    }
}

fn sign_token(secret: &str, ip: &str, ua: &str, nonce: &str, exp: i64) -> String {
    let p = TokenPayload {
        ip: ip.to_string(),
        ua: ua.to_string(),
        nonce: nonce.to_string(),
        exp,
    };
    let body = serde_json::to_vec(&p).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&body);
    let sig = mac.finalize().into_bytes();
    format!("{}.{}", URL_SAFE_NO_PAD.encode(&body), URL_SAFE_NO_PAD.encode(sig))
}
