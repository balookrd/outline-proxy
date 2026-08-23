//! Upper bounds on how long a carrier dial may take, and the single knob that
//! scales them.
//!
//! Every branch of the dial fan-out needs a bound of its own: neither
//! `TcpStream::connect`, nor the TLS/h2/h3 handshakes, nor opening a stream on a
//! pooled connection enforces a deadline. Without one, a server in a network
//! black hole stalls the `h3 → h2 → h1` chain for the OS SYN-retransmit budget
//! (Linux ~127 s, macOS ~75 s) or a QUIC `max_idle_timeout`, and the failover
//! that `report_runtime_failure` drives never gets its turn.
//!
//! The defaults suit a broadband or LTE path, where a fresh TLS dial is a
//! handful of round trips over a fat pipe. They do **not** suit an edge-class
//! link: on 2G a single round trip runs close to a second and the certificate
//! chain alone takes seconds to clock out, so a 10 s budget expires
//! mid-handshake. Every attempt is then scored a failure, the uplink is marked
//! down, and the retries consume the little bandwidth the handshake needed in
//! the first place — the tunnel converges on carrying nothing at all. Raising
//! `[dial] timeout_secs` trades worst-case failover latency for the
//! ability to complete a handshake on such a link.
//!
//! The budget is not fixed for the process: [`set_dial_timeout`] re-sizes it
//! when the link underneath changes, so a phone that starts on Wi-Fi and walks
//! into a 2G cell widens the bound instead of failing every dial until someone
//! reconnects it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::info;

/// Bound for establishing a fresh carrier (TCP + TLS + HTTP upgrade, or the
/// QUIC + HTTP/3 handshake) when nothing is configured.
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Never let configuration shrink a dial below this: under a couple of seconds
/// even a healthy LTE path loses handshakes, which would turn the knob into a
/// self-inflicted outage.
const MIN_DIAL_TIMEOUT: Duration = Duration::from_secs(2);

/// Nor stretch it past this: beyond a couple of minutes the bound stops being a
/// bound — the OS retransmit budget takes over and failover is masked anyway.
const MAX_DIAL_TIMEOUT: Duration = Duration::from_secs(120);

/// H3 opens its stream on a connection whose handshake is already done, so it
/// keeps the proportion the hand-tuned constants had: 7 s against 10 s. H2 keeps
/// the full budget, as its constant did.
const H3_STREAM_NUMERATOR: u32 = 7;
const H3_STREAM_DENOMINATOR: u32 = 10;

/// Configured budget in milliseconds, or `0` for "nothing set — use the
/// default".
///
/// An atomic rather than a `OnceLock` because the right budget is a property of
/// the *network*, not of the process: a phone that starts on Wi-Fi and walks
/// into a 2G cell needs the wider bound without tearing the tunnel down, and an
/// embedder that can see the link change is the only party that knows. Each
/// dial reads the value once when it starts, so a change applies to dials that
/// begin after it and never moves the deadline of one already in flight.
static DIAL_TIMEOUT_MS: AtomicU64 = AtomicU64::new(0);

/// Install the configured dial budget from config. `None` leaves the default.
pub fn init_dial_timeout(timeout: Option<Duration>) {
    if let Some(configured) = timeout {
        store_dial_timeout(configured);
    }
}

/// Re-size the budget for the link now underneath the tunnel.
///
/// Meant for an embedder that watches the platform's network state (the Android
/// `VpnService`). Takes effect on the next dial; in-flight handshakes keep the
/// deadline they started with. `None` restores the default — the caller saying
/// "this link needs nothing special", not "leave whatever was there".
pub fn set_dial_timeout(timeout: Option<Duration>) {
    match timeout {
        Some(configured) => store_dial_timeout(configured),
        None => {
            if DIAL_TIMEOUT_MS.swap(0, Ordering::Relaxed) != 0 {
                info!("carrier-dial budget reset to the default");
            }
        },
    }
}

fn store_dial_timeout(configured: Duration) {
    let clamped = clamp_dial_timeout(configured);
    let millis = clamped.as_millis() as u64;
    if DIAL_TIMEOUT_MS.swap(millis, Ordering::Relaxed) != millis {
        info!(budget_secs = clamped.as_secs(), "carrier-dial budget set");
    }
}

/// Bound for establishing a fresh carrier of any family.
pub(crate) fn fresh_connect_timeout() -> Duration {
    match DIAL_TIMEOUT_MS.load(Ordering::Relaxed) {
        0 => DEFAULT_DIAL_TIMEOUT,
        millis => Duration::from_millis(millis),
    }
}

/// Bound for issuing a CONNECT/upgrade request on an already-established H2
/// connection and reading its response.
pub(crate) fn open_stream_timeout() -> Duration {
    fresh_connect_timeout()
}

/// The H3 flavour of [`open_stream_timeout`].
pub(crate) fn h3_open_stream_timeout() -> Duration {
    h3_stream_from(fresh_connect_timeout())
}

fn clamp_dial_timeout(configured: Duration) -> Duration {
    configured.clamp(MIN_DIAL_TIMEOUT, MAX_DIAL_TIMEOUT)
}

fn h3_stream_from(base: Duration) -> Duration {
    (base * H3_STREAM_NUMERATOR / H3_STREAM_DENOMINATOR).max(Duration::from_secs(1))
}

#[cfg(test)]
#[path = "tests/dial_timeouts.rs"]
mod tests;
