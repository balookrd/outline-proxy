//! Probe-resistant fall-through for failed handshakes.
//!
//! When VLESS or Shadowsocks reject an inbound stream because of a parser
//! or auth failure, an active probe with a stopwatch can fingerprint the
//! protocol by *when* the close arrives: the VLESS parser bails on the
//! 18th byte (`InvalidVersion` / unknown UUID), the SS-AEAD path stalls
//! until enough bytes for an AEAD block arrive (and otherwise sits on the
//! 30 s handshake timeout), and a benign WebSocket endpoint usually just
//! drops the connection. The sink helpers below unify those response
//! shapes by holding the stream open after a rejection and silently
//! consuming further bytes from the peer until a handshake-equivalent
//! timeout or a small byte cap fires. The peer ends up seeing an
//! "unfinished handshake" instead of a sharp parser-driven close.

use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::sleep,
};

use super::{super::constants::SS_TCP_HANDSHAKE_TIMEOUT_SECS, ws_socket::WsSocket};

/// Marker error layered into an `anyhow::Error` chain by the protocol
/// handshake/auth paths after they have run the connection through the
/// probe-resistance sink. The outer session guard checks for this marker
/// via [`is_handshake_rejected`] and maps the close to
/// `DisconnectReason::HandshakeRejected` instead of `Error`, so probe
/// activity is visible in metrics separately from genuine relay errors.
#[derive(Debug, thiserror::Error)]
#[error("handshake rejected (probe-sinked)")]
pub(in crate::server) struct HandshakeRejectedMarker;

/// Returns `true` if the error chain contains a [`HandshakeRejectedMarker`]
/// — i.e. the failure was a handshake/auth rejection that already went
/// through the probe-resistance sink.
pub(in crate::server) fn is_handshake_rejected(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<HandshakeRejectedMarker>().is_some())
}

/// Cap on the volume of post-rejection junk we are willing to read into
/// /dev/null per stream. 64 KiB is small enough that a probe burst can
/// trip the cap before the timeout fires, large enough that legitimate
/// probe-shaped traffic (a couple of KB of garbage) plays out under the
/// time bound — keeping the timing signal close to a stalled SS-AEAD
/// handshake rather than to an instant cap-cutoff.
const SINK_MAX_BYTES: usize = 64 * 1024;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

/// Test-only override for the sink timeout, in milliseconds. `0` means
/// "use the production default". Tests set this to a small value so the
/// sink-mode regression coverage runs in seconds rather than 30 s per
/// case. Shipping code never touches this — there is no public setter
/// outside `cfg(test)`.
#[cfg(test)]
static TEST_TIMEOUT_OVERRIDE_MS: AtomicU64 = AtomicU64::new(0);

/// Acquire-and-set guard for the sink-timeout override. Locks a single
/// process-wide mutex so probe tests in different files do not race on
/// the atomic; clears the override and releases the mutex on drop.
/// The mutex matters because cargo test runs tests in parallel by
/// default and the override is shared state.
#[cfg(test)]
pub(in crate::server) struct TestTimeoutOverride {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestTimeoutOverride {
    pub(in crate::server) fn set(d: Duration) -> Self {
        static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let lock = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        TEST_TIMEOUT_OVERRIDE_MS.store(d.as_millis() as u64, Ordering::Relaxed);
        Self { _lock: lock }
    }
}

#[cfg(test)]
impl Drop for TestTimeoutOverride {
    fn drop(&mut self) {
        TEST_TIMEOUT_OVERRIDE_MS.store(0, Ordering::Relaxed);
    }
}

fn sink_timeout() -> Duration {
    #[cfg(test)]
    {
        let ms = TEST_TIMEOUT_OVERRIDE_MS.load(Ordering::Relaxed);
        if ms > 0 {
            return Duration::from_millis(ms);
        }
    }
    Duration::from_secs(SS_TCP_HANDSHAKE_TIMEOUT_SECS)
}

/// Drain WebSocket frames from `reader` to /dev/null until the
/// handshake-equivalent timeout fires, the peer hangs up, or the byte
/// cap trips. The caller is expected to send a `Close` frame and tear
/// down its outbound channels *after* this returns — the sink itself
/// only consumes inbound traffic.
pub(super) async fn sink_ws<T: WsSocket>(reader: &mut T::Reader) {
    let deadline = sleep(sink_timeout());
    tokio::pin!(deadline);
    let mut drained: usize = 0;
    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => return,
            result = T::recv(reader) => match result {
                Ok(Some(msg)) => {
                    drained = drained.saturating_add(T::msg_len(&msg));
                    if drained >= SINK_MAX_BYTES {
                        return;
                    }
                },
                Ok(None) | Err(_) => return,
            }
        }
    }
}

/// `AsyncRead` analogue of [`sink_ws`] for plain-TCP and raw-QUIC paths
/// where there is no WS framing — we just discard bytes off the stream.
pub(in crate::server) async fn sink_async_read<R: AsyncRead + Unpin>(reader: &mut R) {
    let deadline = sleep(sink_timeout());
    tokio::pin!(deadline);
    let mut drained: usize = 0;
    let mut buf = [0_u8; 4096];
    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => return,
            result = reader.read(&mut buf) => match result {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    drained = drained.saturating_add(n);
                    if drained >= SINK_MAX_BYTES {
                        return;
                    }
                },
            }
        }
    }
}
