use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::lookup_host;
use tracing::warn;

use crate::dns_cache::{AddrPreference, DnsCache};

/// Resolves `host:port` through the supplied cache, returning addresses
/// pre-sorted/filtered by the `ipv6_first` and `ipv4_only` preferences.
///
/// The cache key includes `AddrPreference`, so the sort/filtering happens once at insert
/// time; each cache hit returns a ready slice without re-sorting.
pub async fn resolve_host_with_preference(
    cache: &DnsCache,
    host: &str,
    port: u16,
    context: &str,
    ipv6_first: bool,
    ipv4_only: bool,
) -> Result<Arc<[SocketAddr]>> {
    let pref = AddrPreference::from_client_flags(ipv6_first, ipv4_only);
    if let Some(addrs) = cache.get(host, port, pref) {
        return Ok(addrs);
    }
    match lookup_host((host, port)).await {
        Ok(resolved) => {
            let mut addrs: Vec<SocketAddr> = resolved.collect();
            if ipv4_only {
                addrs.retain(SocketAddr::is_ipv4);
            } else {
                addrs.sort_by_key(|addr| {
                    if ipv6_first {
                        if addr.is_ipv6() { 0 } else { 1 }
                    } else if addr.is_ipv4() {
                        0
                    } else {
                        1
                    }
                });
            }
            let addrs: Arc<[SocketAddr]> = addrs.into();
            cache.insert(host, port, pref, Arc::clone(&addrs));
            Ok(addrs)
        },
        Err(err) => {
            if let Some(stale) = cache.get_stale(host, port, pref) {
                warn!(
                    host,
                    port,
                    ipv6_first,
                    ipv4_only,
                    error = %err,
                    "DNS lookup failed, using stale cached addresses"
                );
                Ok(stale)
            } else {
                Err(err).with_context(|| context.to_string())
            }
        },
    }
}

#[cfg(test)]
#[path = "tests/dns.rs"]
mod tests;
