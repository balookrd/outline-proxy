//! Same-uplink transparent retry policy for TCP chunk-0 failures.
//!
//! Two cases share this module:
//!
//! * warm-standby stale socket — the standby pool can hand out a transport
//!   whose far end was silently torn down; a single fresh dial on the same
//!   uplink almost always recovers it.
//! * transit/DPI RST on a fresh dial — a brief transit flap at the uplink
//!   egress routinely resets fresh WS handshakes on several uplinks within a
//!   few hundred ms; bounded same-uplink retries with a short backoff recover
//!   the session faster than jumping straight to cross-uplink failover.
//!
//! The orchestration loop in `phase1.rs` decides *when* to apply each policy;
//! the constants, the RST-retry predicate, and the shared
//! "redial → replace → replay → half-close" sequence live here so those two
//! retry branches share their recovery path instead of duplicating it.

use std::time::Duration;

use anyhow::{Context, Result};

use outline_uplink::UplinkManager;
use socks5_proto::TargetAddr;

use super::super::failover::{ActiveTcpUplink, TcpUplinkSource, connect_tcp_uplink_fresh};
use super::replay::ReplayBufState;

/// Maximum number of transparent retries on the *same* uplink when chunk 0
/// dies with a transport-level reset (WebSocket RST / clean Close before any
/// response bytes).  Transit flaps routinely RST fresh WS handshakes on
/// several uplinks within a few hundred milliseconds; silently redialing
/// once or twice avoids surfacing a brief network event to the client as a
/// user-visible disconnect, and is cheaper than a full cross-uplink failover.
pub(super) const CHUNK0_RST_MAX_RETRIES: u8 = 2;

/// Delay between transparent chunk-0 retries.  Short enough that the worst
/// case (two retries) stays well under a second, long enough to let a
/// transit/DPI flap clear before dialing again.
pub(super) const CHUNK0_RST_RETRY_BACKOFF: Duration = Duration::from_millis(300);

/// Returns `true` when the current chunk-0 error warrants another transparent
/// dial of the *same* uplink instead of escalating to cross-uplink failover.
/// Only applied to fresh-dial sources: standby has its own recovery branch,
/// and direct-socket transports do not go through WebSocket.
pub(super) fn should_retry_rst_on_current_uplink(
    source: TcpUplinkSource,
    retries_used: u8,
    error: &anyhow::Error,
) -> bool {
    source == TcpUplinkSource::FreshDial
        && retries_used < CHUNK0_RST_MAX_RETRIES
        && crate::error_class::is_ws_closed(error)
}

/// Reconnects the currently-active uplink candidate with a fresh dial and
/// rewinds the buffered client state onto the new transport so the phase-1
/// loop can continue as if the flap had never happened.
pub(super) async fn redial_current_uplink_and_replay(
    uplinks: &UplinkManager,
    active: &mut ActiveTcpUplink,
    target: &TargetAddr,
    replay: &mut ReplayBufState,
    client_half_closed: bool,
    replay_error_ctx: &'static str,
    half_close_error_ctx: &'static str,
) -> Result<()> {
    let reconnected = connect_tcp_uplink_fresh(uplinks, &active.candidate, target).await?;
    active.replace_transport(reconnected);
    replay.replay_to(&mut active.writer, replay_error_ctx).await?;
    if client_half_closed {
        active
            .writer
            .close()
            .await
            .context(half_close_error_ctx)?;
    }
    Ok(())
}
