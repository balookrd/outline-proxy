//! Accept-loop primitives shared by the SOCKS5 ingress and the HTTP listeners.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

/// Wait for a free connection slot without going deaf to shutdown.
///
/// Returns `None` when shutdown fires first. Awaiting the semaphore on its own
/// is the one place in an accept loop where SIGTERM goes unnoticed: with every
/// permit taken, the loop stays parked until some in-flight connection ends on
/// its own, which for an idle SSH or WebSocket flow can be a long time. Racing
/// the two keeps the drain start time bounded by our own decision rather than
/// by the busiest client's.
pub(crate) async fn acquire_permit_or_shutdown(
    conn_sem: &Arc<Semaphore>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<OwnedSemaphorePermit> {
    tokio::select! {
        permit = Arc::clone(conn_sem).acquire_owned() => {
            Some(permit.expect("semaphore closed"))
        },
        _ = shutdown.changed() => None,
    }
}

#[cfg(test)]
#[path = "tests/accept.rs"]
mod tests;
