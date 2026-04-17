use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::lookup_host;
use tracing::warn;

use crate::config_types::ServerAddr;
use crate::dns_cache::DnsCache;

pub(super) async fn resolve_server_addr(
    cache: &DnsCache,
    addr: &ServerAddr,
    ipv6_first: bool,
) -> Result<SocketAddr> {
    resolve_host_with_preference(
        cache,
        addr.host(),
        addr.port(),
        &format!("failed to resolve {}", addr),
        ipv6_first,
    )
    .await?
    .first()
    .copied()
    .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {}", addr))
}

/// Resolves `host:port` through the supplied cache, returning addresses
/// pre-sorted by the `ipv6_first` preference.
///
/// The cache key includes `ipv6_first`, so the sort happens once at insert
/// time; each cache hit returns a ready slice without re-sorting.
pub async fn resolve_host_with_preference(
    cache: &DnsCache,
    host: &str,
    port: u16,
    context: &str,
    ipv6_first: bool,
) -> Result<Arc<[SocketAddr]>> {
    if let Some(addrs) = cache.get(host, port, ipv6_first) {
        return Ok(addrs);
    }
    match lookup_host((host, port)).await {
        Ok(resolved) => {
            let mut sorted: Vec<SocketAddr> = resolved.collect();
            sorted.sort_by_key(|addr| {
                if ipv6_first {
                    if addr.is_ipv6() { 0 } else { 1 }
                } else if addr.is_ipv4() {
                    0
                } else {
                    1
                }
            });
            let addrs: Arc<[SocketAddr]> = sorted.into();
            cache.insert(host, port, ipv6_first, Arc::clone(&addrs));
            Ok(addrs)
        },
        Err(err) => {
            if let Some(stale) = cache.get_stale(host, port, ipv6_first) {
                warn!(
                    host,
                    port,
                    ipv6_first,
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
