//! Shared TLS / QUIC client configs and shared per-AF endpoints.
//!
//! Three ALPNs are supported, matching the outline-ss-rust server's
//! per-protocol QUIC listener: `vless`, `ss`, `h3`. Each ALPN gets its
//! own lazily-initialised `quinn::ClientConfig`. The underlying UDP
//! endpoints are shared across ALPNs (one per address family — quinn
//! endpoints are protocol-agnostic; ALPN is selected per connection via
//! the client config).

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use hashbrown::HashMap;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;

use crate::bind_udp_socket;

// ── Shared per-AF endpoints ─────────────────────────────────────────────────

static QUIC_CLIENT_ENDPOINT_V4: OnceCell<quinn::Endpoint> = OnceCell::new();
static QUIC_CLIENT_ENDPOINT_V6: OnceCell<quinn::Endpoint> = OnceCell::new();

/// Returns the process-wide shared `quinn::Endpoint` for the given bind
/// address (one per IPv4 / IPv6). Used by both H3 and raw QUIC.
pub(crate) fn shared_quic_endpoint(bind_addr: SocketAddr) -> Result<quinn::Endpoint> {
    let cell = if bind_addr.is_ipv4() {
        &QUIC_CLIENT_ENDPOINT_V4
    } else {
        &QUIC_CLIENT_ENDPOINT_V6
    };
    let endpoint = cell.get_or_try_init(|| {
        let socket = bind_udp_socket(bind_addr, None)?;
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind shared QUIC client endpoint on {bind_addr}"))
    })?;
    Ok(endpoint.clone())
}

// ── Per-ALPN client configs ─────────────────────────────────────────────────

/// Cache of `(ClientConfig, QuicClientConfig)` keyed by ALPN bytes. Built
/// once per ALPN at first use. Sealed behind a single mutex because
/// builds are rare (once per ALPN, ever) and cheap.
static QUIC_CLIENT_CONFIGS: OnceLock<Mutex<HashMap<Vec<u8>, quinn::ClientConfig>>> =
    OnceLock::new();

/// Returns a cloned QUIC client config for `alpn`. Keepalive / idle
/// timeout match the H3 path: PING every 10s, drop after 30s of silence.
/// QUIC datagrams are enabled (RFC 9221) — required by VLESS-UDP and
/// SS-UDP over raw QUIC.
pub(crate) fn quic_client_config(alpn: &[u8]) -> quinn::ClientConfig {
    let cache = QUIC_CLIENT_CONFIGS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock();
    if let Some(existing) = guard.get(alpn) {
        return existing.clone();
    }
    let tls = crate::tls::build_client_config(&[alpn]);
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
        .expect("rustls ALPN config is always QUIC-compatible");
    let mut config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("valid client idle timeout"),
    ));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    config.transport_config(Arc::new(transport));
    guard.insert(alpn.to_vec(), config.clone());
    config
}
