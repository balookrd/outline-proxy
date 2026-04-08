use anyhow::{Context, Result, anyhow};
use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::net::lookup_host;
use tracing::warn;

use crate::dns_cache::DnsCache;
use crate::types::ServerAddr;

static DNS_CACHE: OnceLock<DnsCache> = OnceLock::new();

pub(super) async fn resolve_server_addr(addr: &ServerAddr, ipv6_first: bool) -> Result<SocketAddr> {
    resolve_host_with_preference(
        addr.host(),
        addr.port(),
        &format!("failed to resolve {}", addr),
        ipv6_first,
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow!("DNS resolution returned no addresses for {}", addr))
}

pub(crate) async fn resolve_host_with_preference(
    host: &str,
    port: u16,
    context: &str,
    ipv6_first: bool,
) -> Result<Vec<SocketAddr>> {
    let cache = DNS_CACHE.get_or_init(DnsCache::new);

    if let Some(addrs) = cache.get(host, port) {
        return Ok(sort_addrs(addrs, ipv6_first));
    }

    match lookup_host((host, port)).await {
        Ok(resolved) => {
            let addrs: Vec<SocketAddr> = resolved.collect();
            cache.insert(host, port, addrs.clone());
            Ok(sort_addrs(addrs, ipv6_first))
        }
        Err(err) => {
            if let Some(stale) = cache.get_stale(host, port) {
                warn!(
                    host,
                    port,
                    error = %err,
                    "DNS lookup failed, using stale cached addresses"
                );
                return Ok(sort_addrs(stale, ipv6_first));
            }
            Err(err).with_context(|| context.to_string())
        }
    }
}

fn sort_addrs(mut addrs: Vec<SocketAddr>, ipv6_first: bool) -> Vec<SocketAddr> {
    addrs.sort_by_key(|addr| {
        if ipv6_first {
            if addr.is_ipv6() { 0u8 } else { 1u8 }
        } else if addr.is_ipv4() {
            0u8
        } else {
            1u8
        }
    });
    addrs
}
