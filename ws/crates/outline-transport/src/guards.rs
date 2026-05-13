use std::sync::Arc;
use tokio::task::JoinHandle;

use outline_metrics::{
    add_transport_connects_active, add_uplink_open_connections, add_upstream_transports_active,
    current_active_uplink, record_transport_connect, record_uplink_connection_close,
    record_upstream_transport,
};

/// `JoinHandle` newtype that aborts the task on `Drop`.
///
/// Tokio's bare `JoinHandle` only detaches the task on drop — it keeps
/// running. For tasks whose lifetime should be bounded by the owning
/// struct (UDP relay readers, NAT entry pumps, per-connection reader
/// loops) that detachment is a leak vector: any early `?`-return or
/// panic in the parent silently orphans the task, and the task then
/// keeps holding sockets, buffers and `Arc`-shared state for as long as
/// it can find anything to await on (UDP `recv` waits forever).
///
/// Stash one of these in a struct field and the field's natural drop
/// runs `abort()` on every exit path — no manual cleanup needed.
pub struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl AbortOnDrop {
    pub fn new(handle: JoinHandle<()>) -> Self {
        Self(handle)
    }
}

pub(crate) struct TransportConnectGuard {
    source: &'static str,
    mode: &'static str,
    finished: bool,
}

impl TransportConnectGuard {
    pub fn new(source: &'static str, mode: &'static str) -> Self {
        add_transport_connects_active(source, mode, 1);
        record_transport_connect(source, mode, "started");
        Self { source, mode, finished: false }
    }

    pub(crate) fn finish(&mut self, result: &'static str) {
        if !self.finished {
            self.finished = true;
            record_transport_connect(self.source, self.mode, result);
        }
    }
}

impl Drop for TransportConnectGuard {
    fn drop(&mut self) {
        if !self.finished {
            record_transport_connect(self.source, self.mode, "error");
        }
        add_transport_connects_active(self.source, self.mode, -1);
    }
}

/// Identification of the uplink that owns an established upstream transport.
///
/// Attached optionally to [`UpstreamTransportGuard`] so the guard's `Drop`
/// can decrement the per-uplink open-connection gauge and classify the
/// closing connection against the still-active uplink — see
/// `outline_ws_rust_uplink_open_connections` and
/// `outline_ws_rust_uplink_connection_close_total` in the dashboard's
/// `Routing Policy / Inactive uplink leak` section.
///
/// `transport` is the wire-side label (`"tcp"` or `"udp"`), matched against
/// the per-transport active-uplink slot in [`outline_metrics::current_active_uplink`].
#[derive(Debug, Clone)]
pub struct UplinkConnectionBinding {
    pub group: Arc<str>,
    pub transport: &'static str,
    pub uplink: Arc<str>,
}

impl UplinkConnectionBinding {
    pub fn new(
        group: impl Into<Arc<str>>,
        transport: &'static str,
        uplink: impl Into<Arc<str>>,
    ) -> Self {
        Self {
            group: group.into(),
            transport,
            uplink: uplink.into(),
        }
    }
}

pub struct UpstreamTransportGuard {
    source: &'static str,
    protocol: &'static str,
    /// Optional uplink attribution. Present for connections dialled through a
    /// concrete uplink (the common case — socks5 dispatch, TUN, standby pool,
    /// VLESS UDP); absent for the rare paths that don't have a single owning
    /// uplink (probe loops use the manager's per-slot warm cache directly,
    /// and tests that don't care about the per-uplink dimension).
    uplink_binding: Option<UplinkConnectionBinding>,
}

impl UpstreamTransportGuard {
    pub fn new(source: &'static str, protocol: &'static str) -> Arc<Self> {
        add_upstream_transports_active(source, protocol, 1);
        record_upstream_transport(source, protocol, "opened");
        Arc::new(Self {
            source,
            protocol,
            uplink_binding: None,
        })
    }

    /// Construct a guard attributed to a concrete uplink. In addition to the
    /// source/protocol bookkeeping done by [`Self::new`], this variant
    /// increments the per-uplink open-connection gauge and arranges for the
    /// matching close-time classification on `Drop`.
    pub fn new_with_uplink(
        source: &'static str,
        protocol: &'static str,
        binding: UplinkConnectionBinding,
    ) -> Arc<Self> {
        add_upstream_transports_active(source, protocol, 1);
        record_upstream_transport(source, protocol, "opened");
        add_uplink_open_connections(&binding.group, binding.transport, &binding.uplink, 1);
        Arc::new(Self {
            source,
            protocol,
            uplink_binding: Some(binding),
        })
    }

    /// Attach an uplink binding to a freshly-minted guard. Designed for the
    /// post-construction wiring path used by transports whose constructors
    /// pre-date the per-uplink attribution metrics (UDP-WS, VLESS UDP/QUIC
    /// mux): the call-site that knows the uplink owns the only `Arc<>`
    /// reference at this point, so `Arc::get_mut` succeeds and we can
    /// upgrade the existing guard in place. If the `Arc` has already been
    /// shared (no longer holdable as `&mut`) the function silently no-ops —
    /// the source/protocol attribution stays in place but the per-uplink
    /// gauge is not affected. That fallback is rare in practice and keeps
    /// the API infallible at call-sites.
    pub fn attach_uplink_binding(this: &mut Arc<Self>, binding: UplinkConnectionBinding) {
        let Some(guard) = Arc::get_mut(this) else { return };
        if guard.uplink_binding.is_some() {
            return;
        }
        add_uplink_open_connections(&binding.group, binding.transport, &binding.uplink, 1);
        guard.uplink_binding = Some(binding);
    }
}

impl Drop for UpstreamTransportGuard {
    fn drop(&mut self) {
        record_upstream_transport(self.source, self.protocol, "closed");
        add_upstream_transports_active(self.source, self.protocol, -1);
        if let Some(binding) = self.uplink_binding.as_ref() {
            add_uplink_open_connections(&binding.group, binding.transport, &binding.uplink, -1);
            // Classify against the currently-active uplink so the dashboard
            // can isolate "stranded after switchover" closes from the normal
            // close stream. `unknown` covers `PerFlow` scope (no active
            // pointer published) — keeping a separate bucket avoids hiding
            // those closes inside `active`.
            let classification = match current_active_uplink(&binding.group, binding.transport) {
                Some(active) if active.as_ref() == binding.uplink.as_ref() => "active",
                Some(_) => "inactive",
                None => "unknown",
            };
            record_uplink_connection_close(
                &binding.group,
                binding.transport,
                &binding.uplink,
                classification,
            );
        }
    }
}
