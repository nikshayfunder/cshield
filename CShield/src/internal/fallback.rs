use redis::AsyncCommands;

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

    pub async fn get_html(&self, server_key: &str) -> Option<Vec<u8>> {
        if let Some(client) = &self.client {
            if let Ok(mut conn) = client.get_async_connection().await {
                let key = format!("error:edge-down:{}", server_key);
                if let Ok(val) = conn.get::<_, Vec<u8>>(key).await {
                    return Some(val);
                }
            }
        }
        None
    }

    pub async fn start_file_refresher(&self, server_key: String, path: String, interval: std::time::Duration) {
        if self.client.is_none() { return; }
        let client = self.client.as_ref().unwrap().clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                if let Ok(mut conn) = client.get_async_connection().await {
                    if let Ok(content) = tokio::fs::read(&path).await {
                        let key = format!("error:edge-down:{}", server_key);
                        let _: () = conn.set(key, content).await.unwrap_or(());
                    }
                }
            }
        });
    }
}
