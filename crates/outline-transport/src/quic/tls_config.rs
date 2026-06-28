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
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hashbrown::HashMap;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;

use crate::bind_udp_socket;
use crate::fingerprint_profile::TlsFingerprint;

// ── Per-process QUIC transport parameter jitter ─────────────────────────────
//
// `max_idle_timeout` is a QUIC transport parameter (wire id 0x0001) sent in
// the Initial handshake packet and is therefore visible to passive observers.
// `keep_alive_interval` controls the cadence of PING frames, observable as
// timing. Fixing both to compile-time constants makes every instance of this
// client immediately identifiable by fingerprint. A small per-process random
// jitter (derived once at startup and held for the lifetime of the process)
// is enough to break that trivially stable fingerprint across restarts.

static QUIC_PARAM_SEED: OnceLock<u16> = OnceLock::new();

/// Returns a per-process u16 drawn once at startup and stable afterwards.
fn quic_param_seed() -> u16 {
    *QUIC_PARAM_SEED.get_or_init(rand::random::<u16>)
}

/// Apply the shared per-process keep-alive / idle-timeout jitter to a client
/// QUIC transport config, so different client instances produce distinct timing
/// fingerprints. The same seed drives the raw-QUIC and H3 carriers, so both
/// move together rather than splitting into two stable fingerprints. Ranges
/// keep `idle_timeout > 2 × keep_alive_interval`:
///   keep_alive:   8..=12 s  (seed bits [2:0])
///   idle_timeout: 28..=35 s  (seed bits [6:3])
pub(crate) fn apply_quic_jitter(transport: &mut quinn::TransportConfig) {
    let seed = quic_param_seed();
    let keepalive_secs = 8u64 + (seed as u64 % 5);
    let idle_secs = 28u64 + ((seed >> 4) as u64 % 8);
    transport.keep_alive_interval(Some(Duration::from_secs(keepalive_secs)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(idle_secs)
            .try_into()
            .expect("valid client idle timeout"),
    ));
}

// ── Shared per-AF endpoints ─────────────────────────────────────────────────

static QUIC_CLIENT_ENDPOINT_V4: OnceCell<quinn::Endpoint> = OnceCell::new();
static QUIC_CLIENT_ENDPOINT_V6: OnceCell<quinn::Endpoint> = OnceCell::new();

/// Returns the process-wide shared `quinn::Endpoint` for the given bind
/// address (one per IPv4 / IPv6). Used by both H3 and raw QUIC.
///
/// In test mode (when `crate::tls::test_mode_active()` returns true)
/// the cache is bypassed and a fresh endpoint is bound per dial —
/// the cached endpoint's driver task is bound to whichever
/// `#[tokio::test]` runtime first hit the cache and would not survive
/// the next test in the same `cargo test` binary.
pub(crate) fn shared_quic_endpoint(bind_addr: SocketAddr) -> Result<quinn::Endpoint> {
    if crate::tls::test_mode_active() {
        let socket = bind_udp_socket(bind_addr, None)?;
        return quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind QUIC client endpoint on {bind_addr}"));
    }
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

/// Cache of `quinn::ClientConfig` keyed by `(dial fingerprint, ALPN bytes)`,
/// each entry stamped with its build time. The fingerprint is the dial-scoped
/// value set by [`crate::fingerprint_profile::with_dial_fingerprint`] — keying
/// on it (instead of ALPN alone) is what lets raw-QUIC pick up the browser
/// family the dial advertises, and stops the first dial's fingerprint from
/// sticking to every later one. After
/// [`crate::tls::SESSION_TICKET_ROTATION_INTERVAL`] an entry is rebuilt so the
/// QUIC path rotates its session-ticket store on the same cadence as the TLS
/// path. Sealed behind a single mutex because builds are rare and cheap.
static QUIC_CLIENT_CONFIGS: OnceLock<
    Mutex<HashMap<(Option<TlsFingerprint>, Vec<u8>), (quinn::ClientConfig, Instant)>>,
> = OnceLock::new();

// ── QUIC flow-control windows ───────────────────────────────────────────────

// Per-stream / per-connection QUIC receive windows for the raw-QUIC and H3
// carriers. quinn's defaults are sized for low-latency links; on a long-RTT
// tunnel a single carrier stream is throughput-bound by `window / RTT`, which
// caps one TUN flow (e.g. a video download) well below the link's capacity.
// Generous defaults (8 MiB stream / 64 MiB connection) keep the BDP filled
// even at ~1 s RTT; reducible via `[quic]` in config.toml on memory-tight hosts.
static QUIC_STREAM_RECEIVE_WINDOW: OnceLock<u32> = OnceLock::new();
static QUIC_RECEIVE_WINDOW: OnceLock<u32> = OnceLock::new();

const DEFAULT_QUIC_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const DEFAULT_QUIC_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;

/// Initialise the QUIC receive windows from config. Must be called before the
/// first QUIC/H3 dial. Idempotent with equal values; later differing values are
/// ignored (first-writer-wins), mirroring [`crate::init_h2_window_sizes`].
pub fn init_quic_window_sizes(stream: u32, connection: u32) {
    QUIC_STREAM_RECEIVE_WINDOW.get_or_init(|| stream);
    QUIC_RECEIVE_WINDOW.get_or_init(|| connection);
}

fn quic_stream_receive_window() -> u32 {
    *QUIC_STREAM_RECEIVE_WINDOW.get_or_init(|| DEFAULT_QUIC_STREAM_RECEIVE_WINDOW)
}

fn quic_receive_window() -> u32 {
    *QUIC_RECEIVE_WINDOW.get_or_init(|| DEFAULT_QUIC_RECEIVE_WINDOW)
}

/// Apply carrier throughput tuning (receive windows + congestion control) to a
/// QUIC transport config. Shared by the raw-QUIC and H3 carrier builders so
/// both lift the single-stream `window / RTT` ceiling and survive a lossy /
/// throttled WAN path identically.
fn apply_quic_carrier_tuning(transport: &mut quinn::TransportConfig) {
    transport.stream_receive_window(quinn::VarInt::from_u32(quic_stream_receive_window()));
    transport.receive_window(quinn::VarInt::from_u32(quic_receive_window()));
    // BBR instead of quinn's default (Cubic): on a lossy / DPI-throttled
    // international path Cubic reads loss as congestion and collapses the
    // congestion window, capping a single flow far below the link — the bound
    // that a larger receive window alone cannot lift. BBR is model-based and
    // does not treat loss as a backoff signal, so it keeps the pipe full.
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
}

/// Returns a cloned QUIC client config for `alpn` (raw VLESS / SS). Keep-alive
/// and idle timeout carry the shared per-process jitter ([`apply_quic_jitter`]);
/// QUIC datagrams are enabled (RFC 9221) — required by VLESS-UDP and SS-UDP over
/// raw QUIC. The H3 carrier uses [`h3_quic_client_config`] instead (same jitter,
/// datagrams off).
///
/// For the legacy `vless` / `ss` ALPNs the rustls config offers BOTH
/// the MTU-aware sibling (e.g. `vless-mtu`) AND the requested base
/// ALPN in `alpn_protocols`, in that order — newer servers pick the
/// MTU-aware variant and the resulting connection exposes the
/// oversize-stream fallback; older servers pick the base ALPN and
/// the connection behaves exactly as before. Caller branches via
/// [`super::SharedQuicConnection::supports_oversize_stream`].
pub(crate) fn quic_client_config(alpn: &[u8]) -> quinn::ClientConfig {
    let fp = crate::fingerprint_profile::current_dial_fingerprint();
    let cache = QUIC_CLIENT_CONFIGS.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (fp, alpn.to_vec());
    let mut guard = cache.lock();
    if let Some((existing, created_at)) = guard.get(&key)
        && created_at.elapsed() < crate::tls::SESSION_TICKET_ROTATION_INTERVAL
    {
        return existing.clone();
    }
    // Build the offered-ALPN list: MTU-aware sibling first (server
    // picks the highest-preference one it supports), then the base
    // ALPN. Older servers that only know the base ALPN still match.
    let alpn_offered: Vec<&[u8]> = match super::mtu_alpn_for(alpn) {
        Some(mtu_alpn) => vec![mtu_alpn, alpn],
        None => vec![alpn],
    };
    let tls = crate::tls::build_client_config(&alpn_offered);
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
        .expect("rustls ALPN config is always QUIC-compatible");
    let mut config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    apply_quic_jitter(&mut transport);
    apply_quic_carrier_tuning(&mut transport);
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    // VLESS / SS UDP over QUIC carry application UDP datagrams as QUIC
    // datagrams (RFC 9221). The default initial_mtu of 1200 caps the
    // sendable payload at ~1170 B for the first few RTTs while DPLPMTUD
    // probes upward — long enough that real UDP traffic (DNS responses,
    // 1316-byte VLESS-framed payloads on a 1500-Ethernet uplink) is
    // dropped during the warm-up. Bump the floor to 1400 (safe whenever
    // the path can carry standard 1500-byte Ethernet) and explicitly
    // target 1452 — covers the common VLESS / SS oversized cases without
    // waiting for MTU discovery to converge.
    transport.initial_mtu(1400);
    let mut mtu = quinn::MtuDiscoveryConfig::default();
    mtu.upper_bound(1452);
    transport.mtu_discovery_config(Some(mtu));
    config.transport_config(Arc::new(transport));
    guard.insert(key, (config.clone(), Instant::now()));
    config
}

/// Cache of the H3 QUIC client config, keyed by dial fingerprint with a build
/// timestamp — shared by the WS-over-H3 and XHTTP-over-H3 carriers (both dial
/// `h3` under `dial_plan`'s fingerprint scope). Keyed on the fingerprint for the
/// same reason as [`QUIC_CLIENT_CONFIGS`] (so the family reaches the H3
/// ClientHello and the first dial's choice does not stick) and rebuilt on the
/// [`crate::tls::SESSION_TICKET_ROTATION_INTERVAL`] cadence to rotate the
/// session-ticket store.
static H3_QUIC_CLIENT_CONFIGS: OnceLock<
    Mutex<HashMap<Option<TlsFingerprint>, (quinn::ClientConfig, Instant)>>,
> = OnceLock::new();

/// QUIC client config for the H3 carrier (`h3` ALPN). Same per-process jitter
/// as [`quic_client_config`] but, like a browser's HTTP/3 stack, leaves QUIC
/// datagrams disabled — enabling them would add `max_datagram_frame_size` to
/// the Initial, a tell the raw-QUIC path accepts (it needs datagrams for UDP)
/// but the H3 carrier should not carry. `build_client_config` reads the dial
/// fingerprint and the test-root override, so a fresh process that installs the
/// override before the first dial still captures it.
pub(crate) fn h3_quic_client_config() -> quinn::ClientConfig {
    let fp = crate::fingerprint_profile::current_dial_fingerprint();
    let cache = H3_QUIC_CLIENT_CONFIGS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock();
    if let Some((existing, created_at)) = guard.get(&fp)
        && created_at.elapsed() < crate::tls::SESSION_TICKET_ROTATION_INTERVAL
    {
        return existing.clone();
    }
    let tls = crate::tls::build_client_config(&[b"h3"]);
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
        .expect("h3 rustls config is always QUIC-compatible");
    let mut config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    apply_quic_jitter(&mut transport);
    apply_quic_carrier_tuning(&mut transport);
    // The H3 carrier's UDP rides QUIC *streams*, not datagrams, so disable
    // datagram receive — otherwise quinn's default advertises
    // `max_datagram_frame_size` in the Initial, a transport-parameter a browser
    // HTTP/3 stack would not send (raw QUIC keeps it; it needs datagrams).
    transport.datagram_receive_buffer_size(None);
    config.transport_config(Arc::new(transport));
    guard.insert(fp, (config.clone(), Instant::now()));
    config
}

#[cfg(test)]
#[path = "tests/tls_config.rs"]
mod tests;
