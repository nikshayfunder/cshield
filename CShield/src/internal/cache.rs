use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub status: i32,
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
}

pub struct Store {
    client: Option<redis::Client>,
}

impl Store {
    pub fn new(addr: &str, pw: &str, db: i32) -> Self {
        let client = if !addr.is_empty() {
            let url = format!("redis://:{}@{}/{}", pw, addr, db);
            redis::Client::open(url).ok()
        } else {
            None
        };
        Self { client }
    }

    pub async fn get(&self, ip: &str, path: &str, method: &str, fp: &str, is_html: bool) -> Option<Entry> {
        if let Some(client) = &self.client {
            if let Ok(mut conn) = client.get_async_connection().await {
                let key = format!("cache:{}:{}:{}:{}:{}", ip, path, method, fp, is_html);
                if let Ok(json) = conn.get::<_, String>(key).await {
                    return serde_json::from_str(&json).ok();
                }
            }
        }
        None
    }

    pub async fn set(&self, ip: &str, path: &str, method: &str, fp: &str, is_html: bool, status: i32, body: Vec<u8>, headers: HashMap<String, String>) {
        if let Some(client) = &self.client {
            if let Ok(mut conn) = client.get_async_connection().await {
                let key = format!("cache:{}:{}:{}:{}:{}", ip, path, method, fp, is_html);
                let entry = Entry { status, body, headers };
                if let Ok(json) = serde_json::to_string(&entry) {
                    let _: () = conn.set_ex(key, json, 10).await.unwrap_or(());
                }
            }
        }
    }
}
