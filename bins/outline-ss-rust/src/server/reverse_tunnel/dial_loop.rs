//! Per-endpoint reconnect loop for the reverse-tunnel dialer.
//!
//! Dials the public `ws` listener, hands the established carrier to the
//! shared raw-SS accept loop, and on disconnect/failure backs off (bounded,
//! jittered) before retrying — until shutdown. One loop per configured
//! endpoint; failures of one endpoint never affect the others or the local
//! listeners.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tracing::{info, warn};

use super::endpoint::{DialError, ReverseDialer, is_auth_failure};
use crate::config::ReverseTunnelEndpoint;
use crate::server::h3::{handle_raw_ss_connection, handle_raw_vless_connection};
use crate::server::shutdown::ShutdownSignal;
use crate::server::transport::{RawSsConnectionCtx, RawVlessConnectionCtx, is_normal_h3_shutdown};

/// Accept-side context for a reverse carrier, selected by the endpoint's
/// configured protocol. Both handlers are agnostic to how the carrier was
/// obtained, so the dialer drives the same loops the forward H3 path uses.
pub(super) enum ReverseAcceptCtx {
    Ss(Arc<RawSsConnectionCtx>),
    Vless(Arc<RawVlessConnectionCtx>),
}

/// Backoff after an authentication failure (pin/cert mismatch). Such a
/// failure does not resolve on retry with the same config — the operator
/// must fix certs/pins (and on `ss` that means a restart, as the reverse
/// config is not hot-reloaded). We still probe occasionally rather than
/// giving up, so a transient peer-side cert problem self-heals once fixed,
/// without hammering the peer with TLS handshakes in the meantime.
const AUTH_BACKOFF: Duration = Duration::from_secs(300);

/// A carrier must stay up at least this long to count as healthy and reset
/// the exponential backoff. A carrier that dies sooner keeps the backoff
/// growing, so an instantly-rejected or flapping peer is not retried in a
/// tight loop.
const STABLE_CARRIER_THRESHOLD: Duration = Duration::from_secs(30);

/// How the last attempt ended — selects the next backoff.
enum Outcome {
    /// Pin/cert authentication failure: long, fixed backoff.
    Auth,
    /// Carrier stayed up long enough to be healthy: reset to the floor.
    Stable,
    /// Network failure or short-lived carrier: keep the exponential backoff.
    Transient,
}

/// Drive one reverse endpoint forever (until shutdown). Setup failure
/// (bad pin / unreadable cert) disables just this loop with a logged error.
pub(super) async fn run_dial_loop(
    ep: ReverseTunnelEndpoint,
    ctx: ReverseAcceptCtx,
    mut shutdown: ShutdownSignal,
) {
    let dialer = match ReverseDialer::new(&ep) {
        Ok(dialer) => dialer,
        Err(error) => {
            warn!(?error, addr = %ep.addr, "reverse tunnel disabled for endpoint: setup failed");
            return;
        },
    };

    let mut backoff = ep.backoff_min;
    loop {
        let outcome = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            result = dialer.dial() => match result {
                Ok(connection) => serve_carrier(dialer.addr(), connection, &ctx).await,
                Err(DialError::Auth(error)) => {
                    metrics::counter!("outline_ss_reverse_tunnel_connects_total", "result" => "failure")
                        .increment(1);
                    warn!(?error, addr = %dialer.addr(),
                        "reverse tunnel auth failed (check pins/certs); backing off");
                    Outcome::Auth
                },
                Err(DialError::Transient(error)) => {
                    metrics::counter!("outline_ss_reverse_tunnel_connects_total", "result" => "failure")
                        .increment(1);
                    warn!(?error, addr = %dialer.addr(), "reverse tunnel dial failed");
                    Outcome::Transient
                },
            },
        };

        // Bounded, jittered backoff before the next attempt — survive a
        // down `ws` or a reconnect storm without a tight loop.
        let nap = match outcome {
            Outcome::Auth => jitter(AUTH_BACKOFF),
            Outcome::Stable => {
                backoff = ep.backoff_min;
                jitter(backoff)
            },
            Outcome::Transient => jitter(backoff),
        };
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(nap) => {},
        }
        if matches!(outcome, Outcome::Transient) {
            backoff = (backoff * 2).min(ep.backoff_max);
        }
    }
}

/// Serve one established carrier to completion and classify how it ended.
/// A peer-side mTLS rejection (`ws` does not trust our client cert) surfaces
/// *here*, not on `dial`: in QUIC/TLS 1.3 the dial completes before the
/// rejection arrives, so the carrier comes up and dies almost immediately
/// with a crypto-range close — detected via the carrier's `close_reason`.
async fn serve_carrier(
    addr: &str,
    connection: quinn::Connection,
    ctx: &ReverseAcceptCtx,
) -> Outcome {
    info!(%addr, "reverse tunnel carrier established");
    metrics::counter!("outline_ss_reverse_tunnel_connects_total", "result" => "success")
        .increment(1);
    metrics::gauge!("outline_ss_reverse_tunnel_active_connections").increment(1.0);

    // Clone the carrier handle (an Arc) so its close reason stays readable
    // after the accept loop consumes the connection.
    let probe = connection.clone();
    let started = Instant::now();
    let carrier = match ctx {
        ReverseAcceptCtx::Ss(ctx) => handle_raw_ss_connection(connection, Arc::clone(ctx)).await,
        ReverseAcceptCtx::Vless(ctx) => {
            handle_raw_vless_connection(connection, Arc::clone(ctx)).await
        },
    };
    metrics::gauge!("outline_ss_reverse_tunnel_active_connections").decrement(1.0);

    if let Some(reason) = probe.close_reason()
        && is_auth_failure(&reason)
    {
        warn!(%addr,
            "reverse tunnel carrier rejected by peer mTLS (check pins/certs); backing off");
        return Outcome::Auth;
    }
    if let Err(error) = carrier
        && !is_normal_h3_shutdown(&error)
    {
        warn!(?error, %addr, "reverse tunnel carrier ended with error");
    }
    if started.elapsed() >= STABLE_CARRIER_THRESHOLD {
        Outcome::Stable
    } else {
        Outcome::Transient
    }
}

/// Equal-jitter backoff: sleep half the interval plus a random share of the
/// other half, so concurrent loops don't reconnect in lockstep.
fn jitter(base: Duration) -> Duration {
    let half = base / 2;
    let extra = rand::rng().random_range(0..=half.as_millis().max(1) as u64);
    half + Duration::from_millis(extra)
}
