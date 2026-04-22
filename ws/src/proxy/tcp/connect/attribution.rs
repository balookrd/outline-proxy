//! Terminal chunk-0 failure attribution.
//!
//! When phase-1 can no longer fail over and must surface the error to the
//! caller, we have to decide which uplink (if any) to blame.  The decision
//! mirrors phase-2's rule so a WebSocket close (including `Close 1013 "try
//! again"`) is not treated as a runtime failure — the uplink itself is
//! healthy, the remote target was simply unreachable, and promoting the error
//! to a cooldown would degrade unrelated sessions using the same uplink.
//!
//! When every attempted uplink stalled before the first response we cannot
//! tell which one actually broke the session, so attribution is suppressed
//! entirely and only a warning is logged.

use tracing::warn;

use outline_uplink::{TransportKind, UplinkManager};

use super::super::failover::ActiveTcpUplink;
use super::phase1::DeferredFailure;

/// Reports (or deliberately suppresses) the terminal chunk-0 failure against
/// the appropriate uplink.  Called on the final phase-1 error path, after any
/// transparent retries and cross-uplink failover have been exhausted.
pub(super) async fn attribute_terminal_chunk0_failure(
    uplinks: &UplinkManager,
    active: &ActiveTcpUplink,
    phase1_error: &anyhow::Error,
    deferred_failures: &[DeferredFailure],
    attempted_uplinks: &[&str],
    error_text: &str,
) {
    if deferred_failures.is_empty() {
        if crate::error_class::is_upstream_runtime_failure(phase1_error) {
            uplinks
                .report_runtime_failure(active.index, TransportKind::Tcp, phase1_error)
                .await;
        } else if crate::error_class::is_ws_closed(phase1_error) {
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
