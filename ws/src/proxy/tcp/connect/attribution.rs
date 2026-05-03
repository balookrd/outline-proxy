//! Terminal chunk-0 failure attribution.
//!
//! When chunk-0 failover can no longer fail over and must surface the error
//! to the caller, we have to decide which uplink (if any) to blame.  The
//! decision mirrors the pinned-relay rule so a WebSocket close (including `Close 1013 "try
//! again"`) is not treated as a runtime failure — the uplink itself is
//! healthy, the remote target was simply unreachable, and promoting the error
//! to a cooldown would degrade unrelated sessions using the same uplink.
//!
//! When every attempted uplink stalled before the first response we cannot
//! tell which one actually broke the session, so attribution is suppressed
//! entirely and only a warning is logged.

use std::collections::VecDeque;

use tracing::warn;

use outline_uplink::{TransportKind, UplinkManager};

use super::super::failover::ActiveTcpUplink;
use super::chunk0_failover::DeferredFailure;

/// Reports (or deliberately suppresses) the terminal chunk-0 failure against
/// the appropriate uplink.  Called on the final chunk-0-failover error path,
/// after any transparent retries and cross-uplink failover have been exhausted.
pub(super) async fn attribute_terminal_chunk0_failure(
    uplinks: &UplinkManager,
    active: &ActiveTcpUplink,
    chunk0_error: &anyhow::Error,
    deferred_failures: &VecDeque<DeferredFailure>,
    attempted_uplinks: &[&str],
    error_text: &str,
) {
    if deferred_failures.is_empty() {
        if crate::error_class::is_upstream_runtime_failure(chunk0_error) {
            uplinks
                .report_runtime_failure(active.index, TransportKind::Tcp, chunk0_error)
                .await;
        } else if crate::error_class::is_ws_closed(chunk0_error) {
            uplinks
                .report_upstream_close(active.index, TransportKind::Tcp)
                .await;
        }
    } else {
        warn!(
            last_uplink = %active.name,
            attempts = attempted_uplinks.len(),
            attempted_uplinks = ?attempted_uplinks,
            error = %error_text,
            "suppressing TCP chunk-0 runtime failure attribution because every attempted uplink stalled before the first response"
        );
    }
}
