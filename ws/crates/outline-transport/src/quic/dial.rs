//! Raw-QUIC connect / reuse path, per ALPN.
//!
//! One `SharedConnectionRegistry` per ALPN — connections to the same
//! `host:port` with different ALPNs are distinct, so they MUST live in
//! separate caches. The endpoint (UDP socket per AF) is shared across
//! ALPNs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;
use tokio::sync::OnceCell;
use tokio::time::timeout;
use tracing::{debug, info};
use url::Url;

use crate::shared_cache::{
    CachedEntry, ConnCloseLog, ConnectionKey, SharedConnectionRegistry,
    classify_by_substrings, log_conn_close, should_reuse_connection, with_reuse,
};
use crate::{
    AbortOnDrop, DnsCache, TransportConnectGuard, TransportOperation, bind_addr_for,
    bind_udp_socket, resolve_host_with_preference,
};

use super::connection::SharedQuicConnection;
use super::tls_config::{quic_client_config, shared_quic_endpoint};

const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Per-ALPN registries ──────────────────────────────────────────────────

type QuicConnectionKey = ConnectionKey;

/// One registry per ALPN. ALPN bytes are interned by reference equality
/// only — callers must always pass the same `'static` constant
/// (`super::ALPN_VLESS` etc).
static ALPN_REGISTRIES: OnceLock<
    Mutex<HashMap<&'static [u8], &'static SharedConnectionRegistry<QuicConnectionKey, SharedQuicConnection>>>,
> = OnceLock::new();

fn registry_for(alpn: &'static [u8]) -> &'static SharedConnectionRegistry<QuicConnectionKey, SharedQuicConnection> {
    let map = ALPN_REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock();
    if let Some(existing) = guard.get(alpn) {
        return existing;
    }
    // Leak: there are at most 3 ALPNs ever (vless / ss / h3) and the
    // registry is process-global, so leaking is the right lifetime.
    let leaked: &'static SharedConnectionRegistry<QuicConnectionKey, SharedQuicConnection> =
        Box::leak(Box::new(SharedConnectionRegistry::new()));
    guard.insert(alpn, leaked);
    leaked
}

/// Periodic GC across every ALPN registry.
pub(crate) async fn gc_shared_quic_connections() {
    let map = ALPN_REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()));
    let snapshot: Vec<&'static SharedConnectionRegistry<QuicConnectionKey, SharedQuicConnection>> = {
        let guard = map.lock();
        guard.values().copied().collect()
    };
    for reg in snapshot {
        reg.gc().await;
    }
}

// ── Public entry point ────────────────────────────────────────────────────

/// Open or reuse a raw-QUIC connection to the uplink host advertised by
/// `url`, negotiating ALPN `alpn` (must be one of [`super::ALPN_VLESS`],
/// [`super::ALPN_SS`], [`super::ALPN_H3`]). Probe sources bypass the
/// shared cache.
pub async fn connect_quic_uplink(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    alpn: &'static [u8],
) -> Result<Arc<SharedQuicConnection>> {
    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let registry = registry_for(alpn);
    let metric_label = metric_label_for(alpn);

    if should_reuse_connection(source) {
        let key = QuicConnectionKey::new(host, port, fwmark);
        with_reuse(
            registry,
            key.clone(),
            |shared| async move {
                if shared.is_open() {
                    outline_metrics::record_transport_connect(source, metric_label, "reused");
                    Ok(shared)
                } else {
                    Err(anyhow!("cached quic connection is closed"))
                }
            },
            || async move {
                let conn = resolve_and_dial(
                    cache, host, port, fwmark, ipv6_first, source, alpn, Some(key), registry,
                )
                .await?;
                Ok((Arc::clone(&conn), conn))
            },
        )
        .await
    } else {
        resolve_and_dial(
            cache, host, port, fwmark, ipv6_first, source, alpn, None, registry,
        )
        .await
    }
}

fn metric_label_for(alpn: &'static [u8]) -> &'static str {
    match alpn {
        b"vless" => "quic-vless",
        b"ss" => "quic-ss",
        b"h3" => "quic-h3",
        _ => "quic",
    }
}

// ── Internal: resolve + dial across all DNS addrs ─────────────────────────

#[allow(clippy::too_many_arguments)]
async fn resolve_and_dial(
    cache: &DnsCache,
    server_name: &str,
    server_port: u16,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    alpn: &'static [u8],
    cache_key: Option<QuicConnectionKey>,
    registry: &'static SharedConnectionRegistry<QuicConnectionKey, SharedQuicConnection>,
) -> Result<Arc<SharedQuicConnection>> {
    let context = "failed to resolve quic uplink host".to_string();
    let server_addrs =
        resolve_host_with_preference(cache, server_name, server_port, &context, ipv6_first).await?;
    if server_addrs.is_empty() {
        return Err(anyhow::Error::new(TransportOperation::DnsResolveNoAddresses {
            host: format!("{server_name}:{server_port}"),
        }));
    }

    let metric_label = metric_label_for(alpn);
    let mut last_error: Option<String> = None;
    for addr in server_addrs.iter() {
        let mut guard = TransportConnectGuard::new(source, metric_label);
        match connect_quic_connection(
            *addr, server_name, fwmark, alpn, cache_key.clone(), registry,
        )
        .await
        {
            Ok(conn) => {
                guard.finish("success");
                return Ok(Arc::new(conn));
            }
            Err(e) => {
                debug!(
                    server_name,
                    server_port,
                    addr = %addr,
                    alpn = %String::from_utf8_lossy(alpn),
                    error = %format!("{e:#}"),
                    "quic dial failed; trying next address"
                );
                last_error = Some(format!("{addr}: {e}"));
            }
        }
    }
    Err(anyhow::Error::new(TransportOperation::Connect {
        target: format!(
            "to any resolved quic[{}] address for {server_name}:{server_port}: {}",
            String::from_utf8_lossy(alpn),
            last_error.unwrap_or_else(|| "unknown error".to_string())
        ),
    }))
}

async fn connect_quic_connection(
    server_addr: SocketAddr,
    server_name: &str,
    fwmark: Option<u32>,
    alpn: &'static [u8],
    cache_key: Option<QuicConnectionKey>,
    registry: &'static SharedConnectionRegistry<QuicConnectionKey, SharedQuicConnection>,
) -> Result<SharedQuicConnection> {
    let bind_addr = bind_addr_for(server_addr);
    let client_config = quic_client_config(alpn);

    let endpoint = if fwmark.is_some() {
        let socket = bind_udp_socket(bind_addr, fwmark)?;
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind QUIC client endpoint on {bind_addr}"))?
    } else {
        shared_quic_endpoint(bind_addr)?
    };

    let connecting = endpoint
        .connect_with(client_config, server_addr, server_name)
        .with_context(|| format!("failed to initiate QUIC connection to {server_addr}"))?;

    let connection = timeout(FRESH_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            anyhow!(
                "raw QUIC fresh connect timed out after {}s to {server_addr}",
                FRESH_CONNECT_TIMEOUT.as_secs()
            )
        })?
        .with_context(|| format!("QUIC handshake failed for {server_addr}"))?;

    if connection.max_datagram_size().is_none() {
        bail!(
            "peer {server_addr} did not negotiate QUIC datagram support — required for outline-quic UDP sessions"
        );
    }

    // Pull the actually-negotiated ALPN out of the rustls handshake
    // data. The `quic_client_config` may have offered both the
    // MTU-aware and base ALPN to the same server in one ClientHello;
    // the peer's choice tells us whether the oversize-stream fallback
    // is available on this connection. Fall back to the offered ALPN
    // if the server didn't echo one (unexpected for outline servers).
    let negotiated_alpn = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .unwrap_or_else(|| alpn.to_vec());

    let id = registry.next_id();
    let sessions_opened = Arc::new(AtomicU64::new(0));
    let sessions_for_driver = Arc::clone(&sessions_opened);
    let opened_at = Instant::now();
    let peer_for_driver = server_addr.to_string();
    let alpn_label = String::from_utf8_lossy(alpn).into_owned();
    info!(
        target: "outline_transport::conn_life",
        id, peer = %server_addr, mode = "quic", alpn = %alpn_label,
        "quic connection opened"
    );

    let connection_for_driver = connection.clone();
    let alpn_for_driver = alpn_label;
    let driver_task = AbortOnDrop::new(tokio::spawn(async move {
        let close = connection_for_driver.closed().await;
        if let Some(cache_key) = cache_key {
            registry.invalidate_if_current(&cache_key, id).await;
        }
        let err_text = close.to_string();
        let class = classify_quic_close(&err_text);
        let expected = is_expected_quic_close(&err_text);
        let fields = ConnCloseLog {
            id,
            peer: &peer_for_driver,
            mode: "quic",
            age_secs: opened_at.elapsed().as_secs(),
            streams: sessions_for_driver.load(Ordering::Relaxed),
        };
        let _ = alpn_for_driver;
        log_conn_close(fields, Some(&err_text), class, expected);
    }));

    Ok(SharedQuicConnection {
        id,
        endpoint,
        connection,
        closed: AtomicBool::new(false),
        sessions_opened,
        vless_udp_demuxer: OnceCell::new(),
        negotiated_alpn,
        oversize_stream: OnceCell::new(),
        _driver_task: driver_task,
    })
}

fn classify_quic_close(err: &str) -> &'static str {
    classify_by_substrings(
        err,
        &[
            (&["ApplicationClose"], "app_close"),
            (&["Timeout", "timed out"], "timeout"),
            (&["closed by client", "Connection closed by client", "LocallyClosed"], "local_close"),
            (&["reset", "Reset"], "rst"),
            (&["tls", "TLS", "certificate"], "tls"),
        ],
        "other",
    )
}

fn is_expected_quic_close(err: &str) -> bool {
    err.contains("LocallyClosed")
        || err.contains("Connection closed by client")
        || err.contains("connection closed by client")
        || err.contains("ApplicationClose")
        || err.contains("Timeout")
}

const _: fn() = || {
    fn assert_cached<T: CachedEntry>() {}
    assert_cached::<SharedQuicConnection>();
};
