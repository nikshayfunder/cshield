use mongodb::{Client, Collection, options::ClientOptions};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use futures::stream::StreamExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    pub cvac: bool,
    pub cwall: bool,
    pub ip_dropping: bool,
    pub captcha: bool,
    pub waf: bool,
    pub rate_limiting: bool,
    #[serde(default)]
    pub extras: HashMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub ip: String,
    pub domain: String,
    pub port: i32,
    pub cdn: bool,
    pub tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_tls: Option<bool>,
    pub features: Features,
    #[serde(skip)]
    pub features_present: bool,
}

pub struct Manager {
    coll: Option<Collection<Config>>,
    by_domain: RwLock<HashMap<String, Config>>,
}

impl Manager {
    pub async fn new(mongo_uri: &str, mongo_db: &str) -> Self {
        let coll = if !mongo_uri.is_empty() {
            if let Ok(opts) = ClientOptions::parse(mongo_uri).await {
                if let Ok(client) = Client::with_options(opts) {
                    let db = client.database(mongo_db);
                    Some(db.collection::<Config>("proxies"))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let mgr = Self {
            coll,
            by_domain: RwLock::new(HashMap::new()),
        };
        mgr.reload().await;
        mgr
    }

    pub async fn reload(&self) {
        if let Some(coll) = &self.coll {
            let mut entries = HashMap::new();
            if let Ok(mut cursor) = coll.find(None, None).await {
                while let Some(result) = cursor.next().await {
                    if let Ok(mut c) = result {
                        if c.domain.is_empty() || c.ip.is_empty() || c.port == 0 {
                            continue;
                        }
                        c.domain = c.domain.to_lowercase();
                        c.features_present = true;
                        entries.insert(c.domain.clone(), c);
                    }
                }
            }
            *self.by_domain.write() = entries;
        }
    }

    pub fn resolve(&self, host: &str) -> Option<Config> {
        let key = host.to_lowercase();
        let stripped = if let Some(idx) = key.find(':') {
            &key[..idx]
        } else {
            &key
        };
        
        let map = self.by_domain.read();
        map.get(stripped).cloned()
    }

    pub fn features_for_host(&self, host: &str) -> Option<Features> {
        self.resolve(host).map(|c| c.features)
    }

    pub async fn upsert_proxy(&self, mut c: Config) -> anyhow::Result<()> {
        c.domain = c.domain.to_lowercase();
        c.features_present = true;
        if let Some(coll) = &self.coll {
            let filter = mongodb::bson::doc! { "domain": &c.domain };
            let update = mongodb::bson::to_document(&c)?;
            let opts = mongodb::options::UpdateOptions::builder().upsert(true).build();
            coll.update_one(filter, mongodb::bson::doc! { "$set": update }, opts).await?;
            self.reload().await;
        } else {
            self.by_domain.write().insert(c.domain.clone(), c);
        }
        Ok(())
    }

    pub async fn delete_proxy(&self, domain: &str) -> anyhow::Result<()> {
        if let Some(coll) = &self.coll {
            let dom = domain.to_lowercase();
            coll.delete_one(mongodb::bson::doc! { "domain": dom }, None).await?;
            self.reload().await;
        } else {
            let dom = domain.to_lowercase();
            self.by_domain.write().remove(&dom);
        }
        Ok(())
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.by_domain.read().keys().cloned().collect()
    }

    pub async fn update_features(&self, domain: &str, f: Features) -> anyhow::Result<()> {
        if let Some(coll) = &self.coll {
             let dom = domain.to_lowercase();
             let doc = mongodb::bson::to_document(&f)?;
             let filter = mongodb::bson::doc! { "domain": dom };
             let update = mongodb::bson::doc! { "$set": { "features": doc } };
             let opts = mongodb::options::UpdateOptions::builder().upsert(true).build();
             coll.update_one(filter, update, opts).await?;
             self.reload().await;
        }
        Ok(())
    }
}

