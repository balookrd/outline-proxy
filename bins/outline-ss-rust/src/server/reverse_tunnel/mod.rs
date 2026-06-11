//! Reverse-tunnel dialer (topology A): this server, behind NAT, dials out to
//! one or more public `outline-ws-rust` QUIC listeners and serves raw
//! Shadowsocks on the bidi streams the peer opens per SOCKS5/TUN session.
//!
//! The carrier direction is inverted (we are the QUIC *client*), but the
//! stream direction and the accept loop are unchanged: quinn lets either
//! peer open bidi streams regardless of who dialed, so the same
//! [`handle_raw_ss_connection`](crate::server::h3::handle_raw_ss_connection)
//! drives the carrier here. One independent reconnect loop per endpoint.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::config::Config;
use crate::server::constants::H3_MAX_CONCURRENT_STREAMS;
use crate::server::services::Built;
use crate::server::shutdown::ShutdownSignal;
use crate::server::transport::{RawQuicSsCtx, RawSsConnectionCtx};

mod dial_loop;
mod endpoint;

/// Spawn one reconnect loop per configured reverse-tunnel endpoint into the
/// server's task set. No-op when `[reverse_tunnel]` is absent/disabled.
pub(in crate::server) fn spawn_reverse_tunnels(
    config: &Config,
    built: &Built,
    tasks: &mut JoinSet<anyhow::Result<()>>,
    shutdown: &ShutdownSignal,
) {
    let Some(reverse) = config.reverse_tunnel.as_ref() else {
        return;
    };
    if reverse.endpoints.is_empty() {
        return;
    }

    // One shared accept-side context for every reverse carrier: the same
    // user keys + services the forward H3 raw-SS path uses, plus a stream
    // admission semaphore bounding concurrent sessions across all peers.
    let raw_ss_ctx = Arc::new(RawQuicSsCtx {
        users: Arc::clone(&built.users),
        services: Arc::clone(&built.services),
    });
    let stream_semaphore = Arc::new(Semaphore::new(H3_MAX_CONCURRENT_STREAMS));
    let ctx = Arc::new(RawSsConnectionCtx { raw_ss_ctx, stream_semaphore });

    for endpoint in &reverse.endpoints {
        let endpoint = endpoint.clone();
        let ctx = Arc::clone(&ctx);
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            dial_loop::run_dial_loop(endpoint, ctx, shutdown).await;
            Ok(())
        });
    }
}
