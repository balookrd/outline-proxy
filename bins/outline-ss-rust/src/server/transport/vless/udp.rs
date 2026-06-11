use std::sync::Arc;

use tracing::{debug, warn};

use super::super::super::resumption::{Parked, ParkedVlessUdpSingle, SessionId};
use super::ctx::{
    UdpUpstream, UpstreamSession, VlessRelayOutcome, VlessRelayState, VlessWsRouteCtx,
    VlessWsServerCtx,
};

/// Atomic park of a single-target VLESS-UDP-over-WS session. Consumes
/// the `Arc<UdpSocket>` from `state.upstream` and inserts a
/// [`Parked::VlessUdpSingle`] entry. The reader task is asked to stop
/// via `cancel.notify_one()` (it acknowledges with
/// [`VlessRelayOutcome::UdpCancelled`]); the socket itself rides into
/// the registry untouched.
pub(super) async fn try_park_vless_udp_single(
    state: &mut VlessRelayState,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    session_id: SessionId,
) -> bool {
    let UdpUpstream {
        socket,
        reader_task,
        cancel,
        target_display,
        client_buffer,
    } = match std::mem::replace(&mut state.upstream, UpstreamSession::None) {
        UpstreamSession::Udp(udp) => udp,
        other => {
            // Shouldn't happen given the caller's match.
            state.upstream = other;
            return false;
        },
    };
    cancel.notify_one();
    match reader_task.into_inner().await {
        Ok(Ok(VlessRelayOutcome::UdpCancelled)) => {},
        Ok(Ok(VlessRelayOutcome::Closed)) => return false,
        Ok(Ok(VlessRelayOutcome::Cancelled(_))) => {
            // Reserved for the TCP harvest path; should never fire here.
            return false;
        },
        Ok(Err(error)) => {
            debug!(?error, "vless udp relay task errored before park; not parking");
            return false;
        },
        Err(join_error) => {
            warn!(?join_error, "vless udp relay task panicked during harvest");
            return false;
        },
    }
    let user = match state.authenticated_user.take() {
        Some(user) => user,
        None => return false,
    };
    let user_counters = match state.user_counters.take() {
        Some(c) => c,
        None => {
            state.authenticated_user = Some(user);
            return false;
        },
    };
    let owner = user.label_arc();
    let parked = ParkedVlessUdpSingle {
        socket: Arc::clone(&socket),
        target_display,
        owner: Arc::clone(&owner),
        user: user.clone(),
        user_counters,
        udp_client_buffer: client_buffer,
    };
    debug!(
        user = %owner,
        path = %route.path,
        "parking vless udp single upstream into orphan registry",
    );
    server
        .orphan_registry
        .park(session_id, Parked::VlessUdpSingle(parked));
    state.authenticated_user = Some(user);
    true
}
