use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::debug;

// The post-client-EOF downstream timeout and SOCKS upstream idle timeout are
// injected at call-site from `TcpTimeouts` (see `crate::proxy::config`).  They
// were previously compile-time constants; defaults now live in
// `TcpTimeouts::DEFAULT` (currently 600 s and 300 s).
//
// post-client-EOF: after the client half-closes, the server may still flush
// in-flight data and then send its own FIN; without a bound a server that
// holds the connection half-open indefinitely would pin two socket FDs.
//
// socks-upstream-idle: closes a SOCKS-through-uplink TCP session once BOTH
// directions have been silent (no real payload bytes) for this long.
// Keepalive frames do NOT count as activity — they only prove the local
// WebSocket writer task is alive, not that the upstream server is still
// reading.

pub(super) enum UplinkOutcome {
    Finished,
    /// Kept in the signature of the drive loop for future use (protocols where
    /// tearing down the upstream side eagerly on client EOF is actually
    /// correct).  Not currently emitted from the SOCKS CONNECT path — see the
    /// comment on client EOF in the uplink task for why we now wait for the
    /// downlink to finish naturally instead. Constructed only in tests; the
    /// production drive loop matches it but never emits it, hence the
    /// `dead_code` allow.
    #[allow(dead_code)]
    CloseSession,
}

/// Outcome of [`drive_tcp_session_tasks`]. Two normal-exit shapes plus the
/// strict-mode abort path that the caller turns into a TCP RST against the
/// SOCKS5 client.
pub(super) enum DriveExit {
    /// Both data tasks finished without external interruption (graceful EOF
    /// from either direction, idle watcher fired, etc.).
    Normal,
    /// The `cancel` future resolved while data tasks were still running
    /// because the manager's active uplink changed away from the one the
    /// session was pinned to. Both tasks have been aborted and awaited.
    /// The caller is responsible for force-closing the client socket (RST)
    /// and emitting the strict-abort metric.
    AbortedOnSwitch(&'static str),
}

/// Optional idle watcher wired into `drive_tcp_session_tasks`.
///
/// The caller creates an `mpsc::unbounded_channel::<()>` before spawning the
/// uplink/downlink futures, clones the sender into both, then passes the
/// receiver here along with the desired timeout.  Every activity token from
/// either direction resets the internal deadline; a deadline expiry aborts
/// both data tasks.  When both senders are dropped (tasks finished
/// naturally), the watcher exits without firing.
///
/// Only genuine payload transfers must signal activity.  Keepalive frames
/// must NOT signal activity — they only prove that the local WebSocket
/// writer task is alive, not that the upstream server is still reading.
/// Counting them as activity would make the watcher useless against the
/// exact stall we are trying to detect.
pub(super) struct IdleGuard {
    activity_rx: mpsc::UnboundedReceiver<()>,
    pub(super) idle_timeout: Duration,
}

impl IdleGuard {
    pub(super) fn new(activity_rx: mpsc::UnboundedReceiver<()>, idle_timeout: Duration) -> Self {
        Self { activity_rx, idle_timeout }
    }

    /// Runs until the deadline expires (returns `true`) or the activity
    /// channel is closed (returns `false`).
    pub(super) async fn run(mut self) -> bool {
        loop {
            match timeout(self.idle_timeout, self.activity_rx.recv()).await {
                Ok(Some(())) => continue,
                Ok(None) => return false,
                Err(_) => return true,
            }
        }
    }
}

pub(super) async fn drive_tcp_session_tasks<U, D, C>(
    uplink: U,
    downlink: D,
    idle: Option<IdleGuard>,
    cancel: C,
    target: Arc<str>,
    post_client_eof_downstream: Duration,
) -> Result<DriveExit>
where
    U: Future<Output = Result<UplinkOutcome>> + Send + 'static,
    D: Future<Output = Result<()>> + Send + 'static,
    C: Future<Output = &'static str> + Send,
{
    let started = tokio::time::Instant::now();
    let uplink_task = tokio::spawn(uplink);
    let downlink_task = tokio::spawn(downlink);
    match idle {
        Some(watcher) => {
            drive_with_idle(
                uplink_task,
                downlink_task,
                watcher,
                cancel,
                started,
                target,
                post_client_eof_downstream,
            )
            .await
        },
        None => {
            drive_without_idle(
                uplink_task,
                downlink_task,
                cancel,
                started,
                target,
                post_client_eof_downstream,
            )
            .await
        },
    }
}

/// Downlink finished first: the server closed cleanly or failed mid-stream.
/// Aborts the uplink task and returns the downlink result.
async fn finish_on_downlink_close(
    joined: std::result::Result<Result<()>, tokio::task::JoinError>,
    uplink_task: tokio::task::JoinHandle<Result<UplinkOutcome>>,
    started: tokio::time::Instant,
    target: &str,
) -> Result<DriveExit> {
    let downlink_result = match joined {
        Ok(result) => result,
        Err(error) => Err(anyhow!("SOCKS TCP downlink task failed: {error}")),
    };
    let elapsed_ms = started.elapsed().as_millis();
    match &downlink_result {
        Ok(()) => debug!(
            target: "outline_ws_rust::session_death",
            elapsed_ms,
            winner = "downlink",
            target_addr = target,
            "downlink finished first, cleanly (server sent Close / upstream EOF)"
        ),
        Err(e) => debug!(
            target: "outline_ws_rust::session_death",
            elapsed_ms,
            winner = "downlink",
            target_addr = target,
            error = %format!("{e:#}"),
            "downlink finished first with error"
        ),
    }
    uplink_task.abort();
    let _ = uplink_task.await;
    downlink_result.map(|()| DriveExit::Normal)
}

/// Uplink finished first.  Behaviour depends on the uplink task's outcome:
///
/// * `Finished` — client sent EOF over a socket transport; wait up to
///   `POST_CLIENT_EOF_DOWNSTREAM_TIMEOUT` for the downlink to flush, then
///   forcibly close.
/// * `CloseSession` — client sent EOF over a WebSocket-backed transport;
///   abort the downlink immediately.
/// * `Err` / `JoinError` — propagate the error after aborting the downlink.
async fn finish_on_uplink_close(
    joined: std::result::Result<Result<UplinkOutcome>, tokio::task::JoinError>,
    downlink_task: tokio::task::JoinHandle<Result<()>>,
    started: tokio::time::Instant,
    target: &str,
    post_client_eof_downstream: Duration,
) -> Result<DriveExit> {
    let elapsed_ms = started.elapsed().as_millis();
    match joined {
        Ok(Ok(UplinkOutcome::Finished)) => {
            debug!(
                target: "outline_ws_rust::session_death",
                elapsed_ms,
                winner = "uplink",
                outcome = "Finished",
                target_addr = target,
                "uplink finished first (client EOF over socket transport), awaiting downlink"
            );
            // The client closed its side; we already sent FIN to the
            // upstream.  Give the upstream a bounded window to flush
            // any remaining data and send its own FIN.  Without a
            // bound, a server that holds the connection half-open
            // indefinitely (VPN, signalling, etc.) would keep this
            // session and its socket FDs alive forever.
            // Keep an abort handle *before* moving the JoinHandle into
            // timeout(): if the deadline fires the JoinHandle is dropped
            // (Tokio does not abort on drop), so without an explicit abort
            // the downlink task would keep running indefinitely, holding
            // Arc<UpstreamTransportGuard> and inflating the active counter.
            let downlink_abort = downlink_task.abort_handle();
            match timeout(post_client_eof_downstream, downlink_task).await {
                Ok(Ok(result)) => result.map(|()| DriveExit::Normal),
                Ok(Err(error)) => Err(anyhow!("SOCKS TCP downlink task failed: {error}")),
                Err(_elapsed) => {
                    debug!(
                        target: "outline_ws_rust::session_death",
                        timeout_secs = post_client_eof_downstream.as_secs(),
                        target_addr = target,
                        "downstream timed out after client EOF — forcibly closing session"
                    );
                    downlink_abort.abort();
                    Ok(DriveExit::Normal)
                },
            }
        },
        Ok(Ok(UplinkOutcome::CloseSession)) => {
            debug!(
                target: "outline_ws_rust::session_death",
                elapsed_ms,
                winner = "uplink",
                outcome = "CloseSession",
                target_addr = target,
                "uplink requested session close (client EOF over websocket-backed transport)"
            );
            downlink_task.abort();
            let _ = downlink_task.await;
            Ok(DriveExit::Normal)
        },
        Ok(Err(error)) => {
            debug!(
                target: "outline_ws_rust::session_death",
                elapsed_ms,
                winner = "uplink",
                outcome = "Error",
                target_addr = target,
                error = %format!("{error:#}"),
                "uplink finished first with error"
            );
            downlink_task.abort();
            let _ = downlink_task.await;
            Err(error)
        },
        Err(error) => {
            downlink_task.abort();
            let _ = downlink_task.await;
            Err(anyhow!("SOCKS TCP uplink task failed: {error}"))
        },
    }
}

/// Classic three-arm driver used when no idle watcher is configured (tests,
/// callers that manage idleness externally). `cancel` is racd alongside the
/// data tasks; resolving it tears the session down and returns
/// [`DriveExit::AbortedOnSwitch`].
async fn drive_without_idle<C>(
    mut uplink_task: tokio::task::JoinHandle<Result<UplinkOutcome>>,
    mut downlink_task: tokio::task::JoinHandle<Result<()>>,
    cancel: C,
    started: tokio::time::Instant,
    target: Arc<str>,
    post_client_eof_downstream: Duration,
) -> Result<DriveExit>
where
    C: Future<Output = &'static str> + Send,
{
    tokio::pin!(cancel);
    tokio::select! {
        biased;
        joined = &mut downlink_task => finish_on_downlink_close(joined, uplink_task, started, &target).await,
        joined = &mut uplink_task => finish_on_uplink_close(joined, downlink_task, started, &target, post_client_eof_downstream).await,
        reason = &mut cancel => abort_session_for_switch(uplink_task, downlink_task, started, &target, reason).await,
    }
}

/// Four-arm driver that races the data tasks against an idle watcher and
/// the external `cancel` future.
///
/// `biased` ordering gives priority to the data-task arms: if a data task
/// completes at the same poll tick as the watcher or cancel, the data task
/// wins and we log the usual `session_death` reason.  The watcher and
/// cancel arms only win when neither task is ready.
async fn drive_with_idle<C>(
    mut uplink_task: tokio::task::JoinHandle<Result<UplinkOutcome>>,
    mut downlink_task: tokio::task::JoinHandle<Result<()>>,
    watcher: IdleGuard,
    cancel: C,
    started: tokio::time::Instant,
    target: Arc<str>,
    post_client_eof_downstream: Duration,
) -> Result<DriveExit>
where
    C: Future<Output = &'static str> + Send,
{
    let idle_timeout_secs = watcher.idle_timeout.as_secs();
    let watcher_fut = watcher.run();
    tokio::pin!(watcher_fut);
    tokio::pin!(cancel);

    tokio::select! {
        biased;
        joined = &mut downlink_task => finish_on_downlink_close(joined, uplink_task, started, &target).await,
        joined = &mut uplink_task => finish_on_uplink_close(joined, downlink_task, started, &target, post_client_eof_downstream).await,
        reason = &mut cancel => abort_session_for_switch(uplink_task, downlink_task, started, &target, reason).await,
        fired = &mut watcher_fut => {
            if fired {
                debug!(
                    target: "outline_ws_rust::session_death",
                    elapsed_ms = started.elapsed().as_millis(),
                    timeout_secs = idle_timeout_secs,
                    winner = "idle",
                    target_addr = %target,
                    "SOCKS TCP session idle for too long — closing"
                );
            } else {
                // Unreachable under normal execution: the activity channel
                // only closes after both data tasks drop their senders, which
                // they only do when their futures complete.  `biased` select
                // ordering above would pick one of the task arms first in
                // that case.  We can still land here on a pathological race
                // where both handles and the watcher become ready in the
                // very same poll — treat it as a silent close rather than
                // panicking.
                debug!(
                    target: "outline_ws_rust::session_death",
                    elapsed_ms = started.elapsed().as_millis(),
                    winner = "idle_channel_closed",
                    target_addr = %target,
                    "activity channel closed concurrently with task completion"
                );
            }
            uplink_task.abort();
            downlink_task.abort();
            let _ = uplink_task.await;
            let _ = downlink_task.await;
            Ok(DriveExit::Normal)
        }
    }
}

/// External cancel signal fired (currently: strict active-uplink switch).
/// Aborts both data tasks, awaits them so their captured locals (and the
/// `Arc<Mutex<…>>` clones of the client TCP halves) are dropped, then
/// returns [`DriveExit::AbortedOnSwitch`] so the caller can force-close the
/// client socket with TCP RST.
async fn abort_session_for_switch(
    uplink_task: tokio::task::JoinHandle<Result<UplinkOutcome>>,
    downlink_task: tokio::task::JoinHandle<Result<()>>,
    started: tokio::time::Instant,
    target: &str,
    reason: &'static str,
) -> Result<DriveExit> {
    debug!(
        target: "outline_ws_rust::session_death",
        elapsed_ms = started.elapsed().as_millis(),
        winner = "active_uplink_switch",
        reason,
        target_addr = target,
        "aborting SOCKS TCP session because active uplink changed"
    );
    uplink_task.abort();
    downlink_task.abort();
    let _ = uplink_task.await;
    let _ = downlink_task.await;
    Ok(DriveExit::AbortedOnSwitch(reason))
}

#[cfg(test)]
#[path = "tests/session.rs"]
mod tests;
