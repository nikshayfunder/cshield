use dashmap::DashMap;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
    capacity: f64,
    rate: f64,
}

pub struct Limiter {
    buckets: DashMap<String, Bucket>,
    rate: f64,
    burst: f64,
}

impl Limiter {
    pub fn new(global_rps: i32, burst: i32, _window_ms: i32) -> Self {
        let rps = if global_rps <= 0 { 100 } else { global_rps };
        let b = if burst <= 0 { rps } else { burst };

        Self {
            buckets: DashMap::new(),
            rate: rps as f64,
            burst: b as f64,
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        // Optimistic check without allocation
        if let Some(mut bucket) = self.buckets.get_mut(key) {
             let now = Instant::now();
             let elapsed = now.duration_since(bucket.last).as_secs_f64();
             bucket.tokens += elapsed * bucket.rate;
             if bucket.tokens > bucket.capacity {
                 bucket.tokens = bucket.capacity;
             }
             bucket.last = now;

             if bucket.tokens < 1.0 {
                 return false;
             }
             bucket.tokens -= 1.0;
             return true;
        }

        // Slow path: insert new bucket
        let mut bucket = self.buckets.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: self.burst,
            last: Instant::now(),
            capacity: self.burst,
            rate: self.rate,
        });

        // We still need to decrement for the first request
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}
