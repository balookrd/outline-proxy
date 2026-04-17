use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

const TTL: Duration = Duration::from_secs(60);

struct Entry {
    addrs: Vec<SocketAddr>,
    expires_at: Instant,
}

pub(crate) struct DnsCache {
    inner: RwLock<HashMap<(String, u16), Entry>>,
}

impl DnsCache {
    pub(crate) fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()) }
    }

    pub(crate) fn get(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {
        let map = self.inner.read();
        let entry = map.get(&(host.to_string(), port))?;
        if Instant::now() < entry.expires_at {
            Some(entry.addrs.clone())
        } else {
            None
        }
    }

    pub(crate) fn get_stale(&self, host: &str, port: u16) -> Option<Vec<SocketAddr>> {
        let map = self.inner.read();
        map.get(&(host.to_string(), port)).map(|entry| entry.addrs.clone())
    }

    pub(crate) fn insert(&self, host: &str, port: u16, addrs: Vec<SocketAddr>) {
        let mut map = self.inner.write();
        map.insert((host.to_string(), port), Entry { addrs, expires_at: Instant::now() + TTL });
    }
}
