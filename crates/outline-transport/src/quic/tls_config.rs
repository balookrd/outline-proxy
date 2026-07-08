//! Shared TLS / QUIC client configs and shared per-AF endpoints.
//!
//! Three ALPNs are supported, matching the outline-ss-rust server's
//! per-protocol QUIC listener: `vless`, `ss`, `h3`. Each ALPN gets its
//! own lazily-initialised `quinn::ClientConfig`. The underlying UDP
//! endpoints are shared across ALPNs (one per address family — quinn
//! endpoints are protocol-agnostic; ALPN is selected per connection via
//! the client config).

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hashbrown::HashMap;
use parking_lot::Mutex;

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

// ── QUIC flow-control windows ───────────────────────────────────────────────

// Per-stream / per-connection QUIC receive windows for the H3 carrier.
// quinn's defaults are sized for low-latency links; on a long-RTT
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
/// QUIC transport config. Lifts the single-stream `window / RTT` ceiling for the
/// H3 carrier and keeps it surviving a lossy / throttled WAN path.
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

/// Cache of the H3 QUIC client config, keyed by dial fingerprint with a build
/// timestamp — shared by the WS-over-H3 and XHTTP-over-H3 carriers (both dial
/// `h3` under `dial_plan`'s fingerprint scope). Keyed on the fingerprint so the
/// browser family reaches the H3 ClientHello and the first dial's choice does
/// not stick, and rebuilt on the [`crate::tls::SESSION_TICKET_ROTATION_INTERVAL`]
/// cadence to rotate the session-ticket store.
static H3_QUIC_CLIENT_CONFIGS: OnceLock<
    Mutex<HashMap<Option<TlsFingerprint>, (quinn::ClientConfig, Instant)>>,
> = OnceLock::new();

/// QUIC client config for the H3 carrier (`h3` ALPN). Carries the shared
/// per-process jitter ([`apply_quic_jitter`]) but, like a browser's HTTP/3
/// stack, leaves QUIC datagrams disabled — enabling them would add
/// `max_datagram_frame_size` to the Initial, a transport-parameter tell a
/// browser HTTP/3 stack would not send. `build_client_config` reads the dial
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
