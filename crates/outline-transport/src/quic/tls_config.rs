//! Shared TLS / QUIC client configs and shared per-AF endpoints.
//!
//! Three ALPNs are supported, matching the outline-ss-rust server's
//! per-protocol QUIC listener: `vless`, `ss`, `h3`. Each ALPN gets its
//! own lazily-initialised `quinn::ClientConfig`. The underlying UDP
//! endpoints are shared across ALPNs (one per address family — quinn
//! endpoints are protocol-agnostic; ALPN is selected per connection via
//! the client config).

use std::sync::{Arc, Once, OnceLock};
use std::time::{Duration, Instant};

use hashbrown::HashMap;
use parking_lot::Mutex;

use crate::fingerprint_profile::TlsFingerprint;

// ── Keep-alive jitter ───────────────────────────────────────────────────────
//
// `max_idle_timeout` (wire id 0x0001) is sent in the Initial and now follows
// the browser profile in `tp_profile` (a browser does not jitter it). The
// keep-alive PING cadence is behaviour, observable only as timing, so it keeps
// a per-process random jitter (derived once at startup and held for the
// lifetime of the process) to avoid a trivially stable timing fingerprint.

static QUIC_PARAM_SEED: OnceLock<u16> = OnceLock::new();

/// Returns a per-process u16 drawn once at startup and stable afterwards.
fn quic_param_seed() -> u16 {
    *QUIC_PARAM_SEED.get_or_init(rand::random::<u16>)
}

// Tests in this crate must not set these: the first-writer-wins `OnceLock`s are
// process-global, so the wire-level transport-parameter tests in
// `quic/tests/tls_config.rs` would see overrides instead of profile values.
static QUIC_CUSTOM_KEEPALIVE: OnceLock<Duration> = OnceLock::new();
static QUIC_CUSTOM_IDLE_TIMEOUT: OnceLock<Duration> = OnceLock::new();

/// Initialise the QUIC keep-alive PING interval from config. Independent of
/// the idle timeout: setting only this leaves `max_idle_timeout` on the
/// browser profile.
pub fn init_quic_keepalive_interval(keepalive: Duration) {
    QUIC_CUSTOM_KEEPALIVE.get_or_init(|| keepalive);
}

/// Initialise the QUIC idle timeout override from config. Setting it makes
/// the Initial's `max_idle_timeout` differ from the dial's browser profile.
pub fn init_quic_idle_timeout(idle_timeout: Duration) {
    QUIC_CUSTOM_IDLE_TIMEOUT.get_or_init(|| idle_timeout);
}

static KEEPALIVE_IDLE_WARNED: Once = Once::new();

/// Warn (once per process) when the configured keep-alive interval is not
/// shorter than the effective idle timeout: the connection would then time
/// out between PINGs. The jittered default (8..=12 s) always fits under the
/// profile's idle, so only operator-set values can trip this.
fn warn_if_keepalive_not_below_idle(keepalive: Duration, idle: Duration) {
    if keepalive >= idle {
        KEEPALIVE_IDLE_WARNED.call_once(|| {
            tracing::warn!(?keepalive, ?idle, "QUIC keepalive is not shorter than idle timeout");
        });
    }
}

/// Keep-alive PING cadence: per-process jitter (8..=12 s) unless configured.
/// PING timing is behaviour, not a transport parameter, so it keeps its
/// jitter even though `max_idle_timeout` now follows the browser profile.
pub(crate) fn apply_quic_keepalive(transport: &mut quinn::TransportConfig) {
    let keepalive = QUIC_CUSTOM_KEEPALIVE
        .get()
        .copied()
        .unwrap_or_else(|| Duration::from_secs(8 + (quic_param_seed() as u64 % 5)));
    transport.keep_alive_interval(Some(keepalive));
}

// ── QUIC flow-control windows ───────────────────────────────────────────────

// Operator overrides (`[quic]`) for the per-stream / per-connection QUIC
// receive windows. When unset the browser profile's windows are advertised.
static QUIC_STREAM_RECEIVE_WINDOW: OnceLock<u32> = OnceLock::new();
static QUIC_RECEIVE_WINDOW: OnceLock<u32> = OnceLock::new();

/// Initialise the QUIC receive-window overrides from config; `None` keeps the
/// browser-profile value. Must be called before the first QUIC/H3 dial. Idempotent with equal
/// values; later differing values are ignored (first-writer-wins), mirroring
/// [`crate::init_h2_window_sizes`].
pub fn init_quic_window_sizes(stream: Option<u32>, connection: Option<u32>) {
    if let Some(v) = stream {
        QUIC_STREAM_RECEIVE_WINDOW.get_or_init(|| v);
    }
    if let Some(v) = connection {
        QUIC_RECEIVE_WINDOW.get_or_init(|| v);
    }
}

/// Transport parameters the Initial advertises, taken from the browser
/// profile; `[quic]` overrides (windows, idle) win when the operator set them.
fn apply_tp_profile(transport: &mut quinn::TransportConfig, tp: &super::tp_profile::QuicTpProfile) {
    let idle = QUIC_CUSTOM_IDLE_TIMEOUT.get().copied().unwrap_or(tp.idle_timeout);
    transport.max_idle_timeout(Some(idle.try_into().expect("valid client idle timeout")));
    transport.stream_receive_window(quinn::VarInt::from_u32(
        QUIC_STREAM_RECEIVE_WINDOW
            .get()
            .copied()
            .unwrap_or(tp.stream_receive_window),
    ));
    transport.receive_window(quinn::VarInt::from_u32(
        QUIC_RECEIVE_WINDOW.get().copied().unwrap_or(tp.receive_window),
    ));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(tp.max_bidi_streams));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(tp.max_uni_streams));
}

/// Apply carrier congestion control to a QUIC transport config (windows come
/// from [`apply_tp_profile`]) so the H3 carrier survives a lossy / throttled
/// WAN path.
fn apply_quic_carrier_tuning(transport: &mut quinn::TransportConfig) {
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

/// QUIC client config for the H3 carrier (`h3` ALPN). Transport parameters
/// follow the dial fingerprint's browser profile ([`apply_tp_profile`]) and
/// QUIC datagrams stay disabled: quinn can advertise `max_datagram_frame_size`
/// only up to 65535 while Chrome sends 65536, so the parameter stays off until
/// it can be sent exactly. `build_client_config` reads the dial
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
    let tp = super::tp_profile::for_fingerprint(fp);
    apply_quic_keepalive(&mut transport);
    apply_tp_profile(&mut transport, tp);
    if let Some(keepalive) = QUIC_CUSTOM_KEEPALIVE.get().copied() {
        let idle = QUIC_CUSTOM_IDLE_TIMEOUT.get().copied().unwrap_or(tp.idle_timeout);
        warn_if_keepalive_not_below_idle(keepalive, idle);
    }
    apply_quic_carrier_tuning(&mut transport);
    // quinn can only advertise `max_datagram_frame_size` up to 65535 while
    // Chrome sends 65536, so the parameter stays off until it can be sent
    // exactly. (Chrome does send it; Apple does not.)
    transport.datagram_receive_buffer_size(None);
    config.transport_config(Arc::new(transport));
    guard.insert(fp, (config.clone(), Instant::now()));
    config
}

/// Endpoint config for one H3 dial, matched to the active dial fingerprint
/// like [`h3_quic_client_config`]: zero-length source CID and no
/// `grease_quic_bit`, as browsers send.
pub(crate) fn h3_endpoint_config() -> quinn::EndpointConfig {
    let fp = crate::fingerprint_profile::current_dial_fingerprint();
    super::tp_profile::for_fingerprint(fp).endpoint_config()
}

#[cfg(test)]
#[path = "tests/tls_config.rs"]
mod tests;
