//! Per-endpoint reconnect loop for the reverse-tunnel dialer.
//!
//! Dials the public `ws` listener, hands the established carrier to the
//! shared raw-SS accept loop, and on disconnect/failure backs off (bounded,
//! jittered) before retrying — until shutdown. One loop per configured
//! endpoint; failures of one endpoint never affect the others or the local
//! listeners.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tracing::{info, warn};

use super::endpoint::ReverseDialer;
use crate::config::ReverseTunnelEndpoint;
use crate::server::h3::handle_raw_ss_connection;
use crate::server::shutdown::ShutdownSignal;
use crate::server::transport::{RawSsConnectionCtx, is_normal_h3_shutdown};

/// Drive one reverse endpoint forever (until shutdown). Setup failure
/// (bad pin / unreadable cert) disables just this loop with a logged error.
pub(super) async fn run_dial_loop(
    ep: ReverseTunnelEndpoint,
    ctx: Arc<RawSsConnectionCtx>,
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
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            result = dialer.dial() => match result {
                Ok(connection) => {
                    info!(addr = %dialer.addr(), "reverse tunnel carrier established");
                    // A clean, long-lived carrier resets the backoff so the
                    // next reconnect is prompt; a carrier that dies almost
                    // immediately still re-enters the bounded backoff below.
                    backoff = ep.backoff_min;
                    if let Err(error) =
                        handle_raw_ss_connection(connection, Arc::clone(&ctx)).await
                        && !is_normal_h3_shutdown(&error)
                    {
                        warn!(?error, addr = %dialer.addr(), "reverse tunnel carrier ended with error");
                    }
                },
                Err(error) => {
                    warn!(?error, addr = %dialer.addr(), "reverse tunnel dial failed");
                },
            },
        }

        // Bounded, jittered backoff before the next attempt — survive a
        // down `ws` or a reconnect storm without a tight loop.
        let nap = jitter(backoff);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(nap) => {},
        }
        backoff = (backoff * 2).min(ep.backoff_max);
    }
}

/// Equal-jitter backoff: sleep half the interval plus a random share of the
/// other half, so concurrent loops don't reconnect in lockstep.
fn jitter(base: Duration) -> Duration {
    let half = base / 2;
    let extra = rand::rng().random_range(0..=half.as_millis().max(1) as u64);
    half + Duration::from_millis(extra)
}
