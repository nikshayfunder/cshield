use std::process::Command;
use parking_lot::Mutex;
use std::collections::HashSet;

pub struct Firewall {
    dropped: Mutex<HashSet<String>>,
}

impl Firewall {
    pub fn new() -> Self {
        // In real app, init chains
        Self {
            dropped: Mutex::new(HashSet::new()),
        }
    }

    pub fn drop_forever(&self, ip: &str) {
        let mut dropped = self.dropped.lock();
        if dropped.contains(ip) { return; }
        
        // Execute iptables
        let _ = Command::new("iptables")
            .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output();
            
        dropped.insert(ip.to_string());
    }
    
    pub fn drop_short(&self, ip: &str, _ttl: std::time::Duration) {
        // In real app, use ipset or similar with timeout
         let _ = Command::new("iptables")
            .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output();
    }
    
    pub fn close(&self) {
        // flush rules
    }
}
