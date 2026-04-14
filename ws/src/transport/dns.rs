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
    let mut server_addrs = if let Some(addrs) = cache.get(host, port) {
        addrs
    } else {
        match lookup_host((host, port)).await {
            Ok(resolved) => {
                let addrs = resolved.collect::<Vec<_>>();
                cache.insert(host, port, addrs.clone());
                addrs
            },
            Err(err) => {
                if let Some(stale) = cache.get_stale(host, port) {
                    warn!(
                        host,
                        port,
                        error = %err,
                        "DNS lookup failed, using stale cached addresses"
                    );
                    stale
                } else {
                    return Err(err).with_context(|| context.to_string());
                }
            },
        }
    };
    server_addrs.sort_by_key(|addr| {
        if ipv6_first {
            if addr.is_ipv6() { 0 } else { 1 }
        } else if addr.is_ipv4() {
            0
        } else {
            1
        }
    });
    Ok(server_addrs)
}
