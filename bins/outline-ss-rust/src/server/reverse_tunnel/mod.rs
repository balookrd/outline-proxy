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

use crate::config::{Config, ReverseProtocol};
use crate::server::constants::REVERSE_TUNNEL_MAX_CONCURRENT_SESSIONS;
use crate::server::services::Built;
use crate::server::shutdown::ShutdownSignal;
use crate::server::transport::{
    RawQuicSsCtx, RawQuicVlessRouteCtx, RawSsConnectionCtx, RawVlessConnectionCtx,
};

use dial_loop::ReverseAcceptCtx;

mod dial_loop;
mod endpoint;

/// Classifier exposed for the server's reverse-tunnel e2e tests, which live
/// outside this module and assert a real mTLS rejection is treated as auth.
#[cfg(test)]
pub(in crate::server) use endpoint::is_auth_failure;

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

    // Shared accept-side contexts reusing the same users / services / routes
    // the forward H3 raw-SS and raw-VLESS paths use, plus one stream-admission
    // semaphore bounding concurrent sessions across all peers and protocols.
    // Each endpoint picks the context matching its configured protocol.
    let stream_semaphore = Arc::new(Semaphore::new(REVERSE_TUNNEL_MAX_CONCURRENT_SESSIONS));
    let ss_ctx = Arc::new(RawSsConnectionCtx {
        raw_ss_ctx: Arc::new(RawQuicSsCtx {
            users: Arc::clone(&built.users),
            services: Arc::clone(&built.services),
        }),
        stream_semaphore: Arc::clone(&stream_semaphore),
    });
    let vless_ctx = Arc::new(RawVlessConnectionCtx {
        vless_server: Arc::clone(&built.services.vless_server),
        raw_vless_route: Arc::new(RawQuicVlessRouteCtx {
            users: Arc::clone(&built.raw_vless_users),
            candidate_users: built.raw_vless_users.iter().map(|u| u.label_arc()).collect(),
        }),
        stream_semaphore: Arc::clone(&stream_semaphore),
    });

    for endpoint in &reverse.endpoints {
        let endpoint = endpoint.clone();
        let ctx = match endpoint.protocol {
            ReverseProtocol::Ss => ReverseAcceptCtx::Ss(Arc::clone(&ss_ctx)),
            ReverseProtocol::Vless => ReverseAcceptCtx::Vless(Arc::clone(&vless_ctx)),
        };
        let shutdown = shutdown.clone();
        tasks.spawn(async move {
            dial_loop::run_dial_loop(endpoint, ctx, shutdown).await;
            Ok(())
        });
    }
}
