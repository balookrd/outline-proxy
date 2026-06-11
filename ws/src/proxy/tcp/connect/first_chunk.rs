//! Reads the first upstream response chunk while concurrently forwarding
//! client bytes onto the current uplink.
//!
//! This is the inner loop of chunk-0 failover that keeps running until either
//! an upstream byte arrives, the upstream closes, the client read errors, or
//! the per-attempt deadline expires.  Extracting it keeps the outer
//! chunk-0-failover loop focused on retry/failover policy.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;

use outline_metrics as metrics;
use outline_uplink::UplinkManager;

use super::super::failover::ActiveTcpUplink;
use super::replay::ReplayBufState;

/// Per-attempt context for [`await_first_upstream_chunk`].
///
/// `initial_attempt_timeout` is used up to the moment `replay` overflows; past
/// that point further cross-uplink failover is impossible, so the deadline is
/// promoted to `upstream_response_timeout` to avoid timing out a genuinely
/// slow-but-working upstream.
pub(super) struct FirstChunkCtx<'a> {
    pub uplinks: &'a UplinkManager,
    pub initial_attempt_timeout: Duration,
    pub upstream_response_timeout: Duration,
}

/// Drives the uplink-read / client-forward select until a chunk0 outcome is
/// decided for the current attempt.
///
/// `client_half_closed` is tracked across attempts by the outer chunk-0-failover loop —
/// it is both read (to take the read-only path once the client has already
/// EOF'd) and written (when this call observes the EOF for the first time).
pub(super) async fn await_first_upstream_chunk(
    ctx: &FirstChunkCtx<'_>,
    active: &mut ActiveTcpUplink,
    client_read: &mut OwnedReadHalf,
    rbuf: &mut [u8],
    replay: &mut ReplayBufState,
    client_half_closed: &mut bool,
) -> Result<Vec<u8>> {
    let mut attempt_timeout = ctx.initial_attempt_timeout;
    let mut deadline = tokio::time::Instant::now() + attempt_timeout;

    loop {
        if *client_half_closed {
            return tokio::time::timeout_at(deadline, active.reader.read_chunk())
                .await
                .map_err(|_| {
                    anyhow!(
                        "upstream did not respond within {}s (chunk 0)",
                        attempt_timeout.as_secs(),
                    )
                })?;
        }

        tokio::select! {
            result = active.reader.read_chunk() => {
                return result;
            }
            n_res = client_read.read(rbuf) => {
                match n_res {
                    Ok(0) => {
                        active
                            .writer
                            .close()
                            .await
                            .context("uplink half-close failed")?;
                        *client_half_closed = true;
                    }
                    Ok(n) => {
                        active
                            .writer
                            .send_chunk(&rbuf[..n])
                            .await
                            .context("uplink write failed")?;
                        metrics::add_bytes(
                            "tcp",
                            "client_to_upstream",
                            ctx.uplinks.group_name(),
                            &active.name,
                            n,
                        );
                        // Do not treat client→upstream bytes during phase 1
                        // as proof that the uplink is healthy yet.  A broken
                        // uplink can still accept writes and then reset or
                        // stall before producing the first response byte.
                        if replay.push(&rbuf[..n]) {
                            // Overflow just triggered — promote to the full
                            // response window immediately so the deadline
                            // reflects the new timeout before we reset it.
                            attempt_timeout = ctx.upstream_response_timeout;
                        }
                        // Treat the deadline as "no response after the last
                        // request activity", not "no response since the
                        // beginning of phase 1".  Computed after the
                        // possible promotion above so the longer window
                        // takes effect on the very same chunk.
                        deadline = tokio::time::Instant::now() + attempt_timeout;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(anyhow!(
                    "upstream did not respond within {}s (chunk 0)",
                    attempt_timeout.as_secs(),
                ));
            }
        }
    }
}
