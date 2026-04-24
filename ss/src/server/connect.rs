use std::{
    net::{SocketAddr, SocketAddrV6},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::{
    net::{TcpSocket, TcpStream, lookup_host},
    time::{Duration, timeout},
};
use tracing::warn;

use crate::{
    fwmark::apply_fwmark_if_needed,
    outbound::{OutboundIpv6, set_ipv6_freebind},
    protocol::TargetAddr,
};

use super::constants::{TCP_CONNECT_TIMEOUT_SECS, TCP_HAPPY_EYEBALLS_DELAY_MS};
use super::dns_cache::DnsCache;

pub(super) async fn resolve_udp_target(
    dns_cache: &DnsCache,
    target: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Result<SocketAddr> {
    match target {
        TargetAddr::Domain(host, port) => {
            if let Some(resolved) = dns_cache.lookup_one(host, *port, prefer_ipv4_upstream) {
                return Ok(resolved);
            }
            let addrs =
                resolve_via_singleflight(dns_cache, host, *port, prefer_ipv4_upstream).await?;
            addrs.first().copied().ok_or_else(|| {
                anyhow!("dns lookup returned no records for {}", target.display_host_port())
            })
        },
        TargetAddr::Socket(addr) => {
            if prefer_ipv4_upstream && addr.is_ipv6() {
                return Err(anyhow!("ipv6 upstream disabled by prefer_ipv4_upstream for {}", addr));
            }
            Ok(*addr)
        },
    }
}

async fn resolve_target_addrs(
    dns_cache: &DnsCache,
    target: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Result<Arc<[SocketAddr]>> {
    match target {
        TargetAddr::Socket(addr) => {
            if prefer_ipv4_upstream && addr.is_ipv6() {
                return Err(anyhow!("ipv6 upstream disabled by prefer_ipv4_upstream for {}", addr));
            }
            Ok(Arc::from(vec![*addr].into_boxed_slice()))
        },
        TargetAddr::Domain(host, port) => {
            if let Some(addrs) = dns_cache.lookup_all(host, *port, prefer_ipv4_upstream) {
                return Ok(addrs);
            }
            resolve_via_singleflight(dns_cache, host, *port, prefer_ipv4_upstream).await
        },
    }
}

async fn resolve_via_singleflight(
    dns_cache: &DnsCache,
    host: &str,
    port: u16,
    prefer_ipv4_upstream: bool,
) -> Result<Arc<[SocketAddr]>> {
    let host_owned = host.to_string();
    dns_cache
        .resolve_or_join(host, port, prefer_ipv4_upstream, move |cache| {
            resolve_and_cache(cache, host_owned, port, prefer_ipv4_upstream)
        })
        .await
}

async fn resolve_and_cache(
    dns_cache: Arc<DnsCache>,
    host: String,
    port: u16,
    prefer_ipv4_upstream: bool,
) -> Result<Arc<[SocketAddr]>> {
    let mut addrs = match lookup_host((host.as_str(), port)).await {
        Ok(resolved) => resolved.collect::<Vec<_>>(),
        Err(error) => {
            if let Some(stale) = dns_cache.lookup_all_stale(&host, port, prefer_ipv4_upstream) {
                warn!(
                    host = %host,
                    port,
                    error = %error,
                    "dns lookup failed, serving stale cached addresses",
                );
                return Ok(stale);
            }
            return Err(error).with_context(|| format!("dns lookup failed for {host}:{port}"));
        },
    };
    if prefer_ipv4_upstream {
        addrs.retain(SocketAddr::is_ipv4);
    }
    if addrs.is_empty() {
        return Err(anyhow!("dns lookup returned no records for {host}:{port}"));
    }
    let addrs: Arc<[SocketAddr]> = Arc::from(addrs.into_boxed_slice());
    dns_cache.store(&host, port, prefer_ipv4_upstream, Arc::clone(&addrs));
    Ok(addrs)
}

pub(super) async fn connect_tcp_target(
    dns_cache: &DnsCache,
    target: &TargetAddr,
    fwmark: Option<u32>,
    prefer_ipv4_upstream: bool,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<TcpStream> {
    let resolved = resolve_target_addrs(dns_cache, target, prefer_ipv4_upstream).await?;
    let ordered = sort_addrs_for_happy_eyeballs(&resolved, prefer_ipv4_upstream);
    connect_tcp_addrs(&ordered, fwmark, outbound_ipv6)
        .await
        .with_context(|| format!("tcp connect failed for {}", target.display_host_port()))
}

pub(super) fn sort_addrs_for_happy_eyeballs(
    addrs: &[SocketAddr],
    prefer_ipv4_upstream: bool,
) -> Vec<SocketAddr> {
    if addrs.len() <= 1 {
        return addrs.to_vec();
    }
    let prefer_ipv6 = !prefer_ipv4_upstream && addrs.first().is_some_and(SocketAddr::is_ipv6);
    let mut ipv4: Vec<SocketAddr> = Vec::new();
    let mut ipv6: Vec<SocketAddr> = Vec::new();

    for &addr in addrs {
        let bucket = if addr.is_ipv6() { &mut ipv6 } else { &mut ipv4 };
        if !bucket.contains(&addr) {
            bucket.push(addr);
        }
    }

    let (primary, secondary) = if prefer_ipv6 { (ipv6, ipv4) } else { (ipv4, ipv6) };
    let mut ordered = Vec::with_capacity(primary.len() + secondary.len());
    let mut p = primary.into_iter();
    let mut s = secondary.into_iter();
    loop {
        match (p.next(), s.next()) {
            (Some(a), Some(b)) => {
                ordered.push(a);
                ordered.push(b);
            }
            (Some(a), None) => {
                ordered.push(a);
                ordered.extend(p);
                break;
            }
            (None, Some(b)) => {
                ordered.push(b);
                ordered.extend(s);
                break;
            }
            (None, None) => break,
        }
    }
    ordered
}

pub(super) async fn connect_tcp_addrs(
    addrs: &[SocketAddr],
    fwmark: Option<u32>,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<TcpStream> {
    let mut attempts = FuturesUnordered::new();
    for (index, addr) in addrs.iter().copied().enumerate() {
        let outbound = outbound_ipv6;
        attempts.push(async move {
            if index > 0 {
                tokio::time::sleep(Duration::from_millis(
                    TCP_HAPPY_EYEBALLS_DELAY_MS * index as u64,
                ))
                .await;
            }
            let result = connect_tcp_addr(addr, fwmark, outbound).await;
            (addr, result)
        });
    }

    let mut last_error = None;
    while let Some((addr, result)) = attempts.next().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some((addr, error)),
        }
    }

    match last_error {
        Some((addr, error)) => Err(error)
            .with_context(|| format!("all tcp connect attempts failed; last address {addr}")),
        None => Err(anyhow!("no socket addresses available for tcp connect")),
    }
}

async fn connect_tcp_addr(
    resolved: SocketAddr,
    fwmark: Option<u32>,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<TcpStream> {
    let socket = if resolved.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .with_context(|| format!("failed to create tcp socket for {resolved}"))?;

    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to tcp socket"))?;

    if let Some(out) = outbound_ipv6
        && resolved.is_ipv6()
    {
        match out
            .random_addr()
            .context("failed to generate random outbound IPv6 address")?
        {
            Some(source) => {
                set_ipv6_freebind(&socket)
                    .with_context(|| "failed to set IPV6_FREEBIND on outbound tcp socket")?;
                let bind = SocketAddr::V6(SocketAddrV6::new(source, 0, 0, 0));
                socket
                    .bind(bind)
                    .with_context(|| format!("failed to bind outbound tcp source {bind}"))?;
            },
            None => {
                tracing::debug!(
                    target = %resolved,
                    source = %out,
                    "outbound IPv6 pool is empty; tcp socket falling back to kernel default source",
                );
            },
        }
    }

    match timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS), socket.connect(resolved)).await {
        Ok(Ok(stream)) => {
            configure_tcp_stream(&stream)
                .with_context(|| format!("failed to configure tcp stream for {resolved}"))?;
            Ok(stream)
        },
        Ok(Err(error)) => Err(error).with_context(|| format!("tcp connect failed for {resolved}")),
        Err(_) => Err(anyhow!(
            "tcp connect timed out after {}s for {resolved}",
            TCP_CONNECT_TIMEOUT_SECS
        )),
    }
}

pub(super) fn configure_tcp_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true).context("failed to enable TCP_NODELAY")
}
