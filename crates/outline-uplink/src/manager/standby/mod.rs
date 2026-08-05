mod ctx;
mod keepalive;
mod refill;

#[cfg(test)]
mod tests;
#[cfg(test)]
use tests::{
    sample_manager_with_live_wire_two, sample_manager_with_vless_fallback, udp_candidate_for_test,
};

#[cfg(test)]
#[path = "tests/wire_dial_tcp.rs"]
mod wire_dial_tcp_tests;

#[cfg(test)]
#[path = "tests/wire_dial_udp.rs"]
mod wire_dial_udp_tests;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::time::{Instant, sleep};
use tracing::debug;

use outline_metrics as metrics;
use outline_transport::{
    DialNetworkOptions, DialResumeOptions, SessionId, TransportDialOptions, TransportOperation,
    TransportStream, UdpSessionTransport, UdpWsTransport, VlessUdpSessionMux, connect_transport,
};

use crate::config::{SsPathKind, UplinkTransport};
use crate::manager::status::PerTransportStatus;
use outline_transport::collections::maybe_shrink_vecdeque;

/// Resolve `(deadline, cap)` from a per-transport status snapshot
/// against the configured mode. Returns the cap when the window is
/// active and the cap is set; falls back to the configured mode
/// otherwise (no window, expired window, or somehow the cap is
/// missing — defensive: a corrupted state should not strand the
/// uplink on a stale mode).
fn capped_or_configured(
    status: &PerTransportStatus,
    configured: crate::config::TransportMode,
) -> crate::config::TransportMode {
    status
        .descent
        .active_cap(tokio::time::Instant::now())
        .unwrap_or(configured)
}

use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

/// What a fresh TCP WebSocket dial presents to the server, and which carrier
/// it asks for. `Default` is the fresh-dial shape: no resume ID, no replay
/// capabilities, cap honoured.
#[derive(Default)]
struct FreshTcpDial {
    /// The Session ID to present as `X-Outline-Resume`. `None` on every fresh
    /// dial (the server mints one); `Some` only on a redial of the session
    /// that was issued this exact ID.
    resume_request: Option<SessionId>,
    ack_prefix_requested: bool,
    symmetric_replay_requested: bool,
    client_acked_offset: u64,
    /// Ask for the *configured* carrier, ignoring any active mode-downgrade
    /// cap. Set only by the paths that rescue a **live** session onto a fresh
    /// carrier — TUN carrier migration and the SOCKS mid-session retry — since
    /// the carrier such a dial lands on is the one that session keeps for the
    /// rest of its life. See
    /// [`UplinkManager::connect_tcp_ws_migrate_with_ack_prefix`].
    bypass_mode_downgrade: bool,
    /// Which wire to dial: `0` is the uplink's primary carrier, `i` is
    /// `fallbacks[i - 1]`. Every existing constructor leaves this at its
    /// `Default` (`0`), which is what it has always done implicitly.
    wire: u8,
}

/// The resume headers a [`FreshTcpDial`] goes out with.
///
/// One rule, applied in one place: a dial that presents **no** Session ID starts
/// a new session, and a new session must advertise both replay capabilities or
/// the server never allocates its downlink ring — see
/// [`DialResumeOptions::new_session`]. Every helper below funnels through here,
/// so the rule cannot hold on the TUN entry point and lapse on the SOCKS one,
/// which is exactly how the fleet ended up with most of its sessions ringless.
///
/// A dial that *does* present an id keeps whatever the caller asked for: the
/// wire-handover redial presents one and asks for nothing, because it owns no
/// replay offset and must not be sent frames it cannot honour.
fn resume_options(dial: &FreshTcpDial) -> DialResumeOptions {
    match dial.resume_request {
        None => DialResumeOptions::new_session(),
        Some(_) => DialResumeOptions {
            resume_request: dial.resume_request,
            ack_prefix_requested: dial.ack_prefix_requested,
            symmetric_replay_requested: dial.symmetric_replay_requested,
            client_acked_offset: dial.client_acked_offset,
        },
    }
}

/// Composes the cache key used by the cross-transport resumption
/// helpers in [`outline_transport::global_resume_cache`]. The form
/// `<uplink_name>#<transport>` keeps TCP and UDP entries separate so
/// the next reconnect cannot pick up another transport's Session ID by
/// accident.
///
/// **SS-UDP only.** The TCP path does not use this cache: a Session ID
/// identifies one *session*, not one uplink, and a single slot per
/// uplink meant a fresh dial of session B could present session A's
/// parked ID — on a resume hit the server re-attaches A's upstream and
/// B silently lands on the wrong destination (the parked target is
/// authoritative server-side). TCP now carries the ID on the session
/// itself: a fresh dial presents none, and only a redial of a given
/// session presents the ID that session was issued. SS-UDP keeps the
/// cache because its sessions are keyed per uplink + destination and
/// re-created wholesale, not per client flow.
///
/// The key is **identity-level** — the parent uplink's display name, or
/// the group name under `shared_resume` — so a fallback dial (different
/// wire family, same uplink) presents the same X-Outline-Resume token as
/// the primary dial.
pub(crate) fn resume_cache_key(uplink_name: &str, transport: &str) -> String {
    format!("{uplink_name}#{transport}")
}

impl UplinkManager {
    /// Returns the effective TCP dial mode for `index`, falling back to
    /// the per-uplink mode-downgrade cap when the configured carrier
    /// has been marked broken by repeated runtime / dial errors. The
    /// cap is family-aware: `WsH3` / `Quic` collapse to `WsH2`,
    /// `XhttpH3` collapses to `XhttpH2`, `XhttpH2` to `XhttpH1`.
    /// A multi-step XHTTP downgrade converges over consecutive dials —
    /// the writer in [`extend_mode_downgrade`] lowers the cap one rank
    /// per observed fallback. Applies to Ws and Vless transports;
    /// Shadowsocks always returns the configured mode unchanged.
    ///
    /// [`extend_mode_downgrade`]: crate::manager::mode_downgrade
    pub async fn effective_tcp_mode(&self, index: usize) -> crate::config::TransportMode {
        let uplink = &self.inner.uplinks[index];
        let configured = uplink.tcp_dial_mode();
        if !matches!(uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return configured;
        }
        self.inner
            .with_status(index, |status| capped_or_configured(&status.tcp, configured))
    }

    /// Same as `effective_tcp_mode`, but for the UDP-over-WS /
    /// UDP-over-QUIC / UDP-over-XHTTP transport.
    pub(crate) async fn effective_udp_mode(&self, index: usize) -> crate::config::TransportMode {
        let uplink = &self.inner.uplinks[index];
        let configured = uplink.udp_dial_mode();
        if !matches!(uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return configured;
        }
        self.inner
            .with_status(index, |status| capped_or_configured(&status.udp, configured))
    }

    /// Pops one connection from the TCP standby pool without falling back to
    /// a fresh dial.  Returns `None` if the pool is empty, or if the popped
    /// entry fails a quick liveness peek (pre-flight check to avoid handing
    /// a stale socket to a fresh SOCKS session).
    ///
    /// The background validation loop runs every 15 s; that is not tight
    /// enough when the upstream closes idle WebSocket connections within a
    /// 10–20 s window.  Re-peeking at acquisition time costs at most
    /// `STANDBY_WS_PEEK_TIMEOUT` (1 ms) per take and closes the race where
    /// a session is handed a socket that server already FIN'd between
    /// validation cycles.  If the peek reports closure, the entry is
    /// dropped and we return `None`; the caller transparently falls back
    /// to `connect_tcp_ws_fresh`, and the pool refill task fills the slot.
    pub async fn try_take_tcp_standby(
        &self,
        candidate: &UplinkCandidate,
    ) -> Option<TransportStream> {
        if !matches!(candidate.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return None;
        }
        let ctx = self.standby_ctx(candidate.index, TransportKind::Tcp).await;
        let ws = ctx.try_take_alive(&candidate.uplink.name).await?;
        // A pooled carrier never passes through the dial path, so this take is
        // the only place its loss probe can be filed. Registering only on dial
        // made measurement coverage follow the *dial* rate rather than the
        // traffic: the busiest gateway showed 3382 reused TCP acquisitions
        // against 11 fresh ones and carried no TCP loss verdict at all, while
        // pushing 1.4 GiB. Registration de-duplicates by carrier identity, so
        // re-filing a carrier that is already known is a no-op.
        self.register_carrier_loss_probe(candidate.index, 0, TransportKind::Tcp, ws.loss_probe());
        Some(ws)
    }

    /// Dials a fresh TCP WebSocket connection, bypassing the standby pool.
    ///
    /// A fresh dial is a **new session**: it presents no `X-Outline-Resume`
    /// ID and lets the server mint one (returned on the stream via
    /// [`TransportStream::issued_session_id`]). Whoever ends up owning the
    /// stream owns that ID and is the only party allowed to present it back
    /// on a redial — see [`Self::connect_tcp_ws_redial_with_ack_prefix`].
    ///
    /// The Ack-Prefix capability is *not* advertised — the dial path used
    /// by initial session setup keeps legacy resume-only semantics. Use
    /// [`Self::connect_tcp_ws_redial_with_ack_prefix`] from the
    /// pinned-relay mid-session retry path to opt in.
    pub async fn connect_tcp_ws_fresh(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<TransportStream> {
        // The advertisement itself is applied by `connect_tcp_ws_fresh_internal`,
        // which asks for both replay capabilities on every dial that presents no
        // id — this one included. See [`DialResumeOptions::new_session`].
        self.connect_tcp_ws_fresh_internal(candidate, source, FreshTcpDial::default())
            .await
    }

    /// Dial `wire` on `candidate` as a fresh session, bypassing the warm pool.
    /// `wire = 0` is the primary carrier and is what every pre-existing caller
    /// gets through [`Self::connect_tcp_ws_fresh`].
    pub async fn connect_tcp_ws_fresh_on_wire(
        &self,
        candidate: &UplinkCandidate,
        wire: u8,
        source: &'static str,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial { wire, ..FreshTcpDial::default() },
        )
        .await
    }

    /// Redial variant for the wire-handover paths (chunk-0 recovery, retry
    /// after a stale standby socket).
    ///
    /// Presents this session's own `resume_request` so the server can
    /// re-attach a still-parked upstream instead of opening a fresh one to the
    /// destination. Deliberately does *not* advertise Ack-Prefix / Symmetric
    /// Replay: those make the server emit replay control frames, and only the
    /// mid-session retry orchestrator owns the ring buffer needed to actually
    /// replay the byte tail. A wire handover has no ring, so it must not ask
    /// for frames it cannot honour.
    pub async fn connect_tcp_ws_redial(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        resume_request: Option<SessionId>,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial { resume_request, ..Default::default() },
        )
        .await
    }

    /// Redial variant for the mid-session retry / soft-switch path.
    ///
    /// Presents `resume_request` (the Session ID **this session** was issued
    /// on its previous carrier, `None` if it never got one) and advertises
    /// `X-Outline-Resume-Ack-Prefix: 1` so the server emits the v1 control
    /// frame on a successful resume hit. Caller must consume it via the SS
    /// reader's `upstream_acked_offset()` before treating bytes as upstream
    /// payload.
    ///
    /// The ID is passed in explicitly rather than read from a process-global
    /// cache: the cache had one slot per uplink, so a concurrent session
    /// could — and on a parking storm would — present a *different* session's
    /// ID and get re-attached to that session's upstream.
    pub async fn connect_tcp_ws_redial_with_ack_prefix(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        resume_request: Option<SessionId>,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial {
                resume_request,
                ack_prefix_requested: true,
                ..Default::default()
            },
        )
        .await
    }

    /// Variant used by the v2 Symmetric Downlink Replay retry path:
    /// presents this session's `resume_request` ID, advertises both v1 and
    /// v2 capabilities, and reports the caller's `client_acked_offset` via
    /// the `X-Outline-Resume-Down-Acked` request header so the server can
    /// emit a precise replay slice. Caller is expected to gate this
    /// on `LoadBalancingConfig::tcp_symmetric_replay_enabled` and to
    /// have advertised v1 already (the dialer's local v2-on-v1 gate
    /// double-checks this on the response side).
    pub async fn connect_tcp_ws_redial_with_symmetric_replay(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        resume_request: Option<SessionId>,
        client_acked_offset: u64,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial {
                resume_request,
                ack_prefix_requested: true,
                symmetric_replay_requested: true,
                client_acked_offset,
                ..Default::default()
            },
        )
        .await
    }

    /// Migration variant of [`Self::connect_tcp_ws_redial_with_ack_prefix`]:
    /// same resume presentation, but asks for the uplink's **configured**
    /// carrier and ignores any active mode-downgrade cap.
    ///
    /// A carrier migration is triggered *by* a carrier death, and that same
    /// death is reported as a runtime failure — which caps the
    /// carrier one rank down (`ws_h3` → `ws_h2`) for `mode_downgrade_secs`.
    /// Honouring the cap here hands every rescued flow a TCP-over-TCP carrier
    /// that it then keeps for the rest of its life (nothing migrates a live
    /// flow back up), so a long download rescued from a dead H3 carrier
    /// crawls where it used to reset and reconnect at full speed. This is the
    /// same reason the migration dial bypasses the candidate filter — see
    /// `redial_tcp_uplink_for_migration` in `outline-tun`.
    ///
    /// The reporter need not be the rescued flow itself. A shared H3 carrier
    /// dies for every flow riding it at once, so the cap is just as likely to
    /// arrive from a sibling flow, the standby refill loop or the probe loop —
    /// which is why the SOCKS mid-session retry
    /// (`redial_for_mid_session_retry` in `outline-ws-rust`) dials through here
    /// too, even though it reports its own runtime failure only after its relay
    /// loop has given up.
    ///
    /// This is not a bet on the configured carrier being alive:
    /// `connect_transport` still falls back `h3 → h2 → h1` inline when the
    /// dial really fails, so a genuinely broken carrier lands the flow exactly
    /// where the cap would have put it — and the resulting stream still
    /// reports `downgraded_from`, so the window is extended as before.
    pub async fn connect_tcp_ws_migrate_with_ack_prefix(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        resume_request: Option<SessionId>,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial {
                resume_request,
                ack_prefix_requested: true,
                bypass_mode_downgrade: true,
                ..Default::default()
            },
        )
        .await
    }

    /// Migration counterpart of
    /// [`Self::connect_tcp_ws_redial_with_symmetric_replay`] — see
    /// [`Self::connect_tcp_ws_migrate_with_ack_prefix`] for why the migration
    /// dial ignores the mode-downgrade cap.
    pub async fn connect_tcp_ws_migrate_with_symmetric_replay(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        resume_request: Option<SessionId>,
        client_acked_offset: u64,
    ) -> Result<TransportStream> {
        self.connect_tcp_ws_fresh_internal(
            candidate,
            source,
            FreshTcpDial {
                resume_request,
                ack_prefix_requested: true,
                symmetric_replay_requested: true,
                client_acked_offset,
                bypass_mode_downgrade: true,
                ..Default::default()
            },
        )
        .await
    }

    /// The carrier a fresh dial asks for: the effective (capped) mode for
    /// `spec`'s wire, or that wire's configured one when the caller bypasses
    /// the cap.
    async fn tcp_dial_mode_for(
        &self,
        candidate: &UplinkCandidate,
        spec: &crate::WireSpec<'_>,
        bypass_mode_downgrade: bool,
    ) -> crate::config::TransportMode {
        if bypass_mode_downgrade {
            spec.dial_mode(crate::Plane::Tcp)
        } else {
            self.effective_tcp_mode_for_wire(candidate.index, spec.wire).await
        }
    }

    async fn connect_tcp_ws_fresh_internal(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        dial: FreshTcpDial,
    ) -> Result<TransportStream> {
        let cache = self.inner.dns_cache.as_ref();
        let spec = crate::WireSpec::of(&candidate.uplink, dial.wire)
            .ok_or_else(|| anyhow!("uplink {} has no wire {}", candidate.uplink.name, dial.wire))?;
        if !spec.is_ws_family() {
            bail!("uplink {} wire {} does not use websocket transport", spec.name, spec.wire);
        }
        metrics::record_warm_standby_acquire("tcp", &self.inner.group_name, spec.name, "miss");
        let mode = self
            .tcp_dial_mode_for(candidate, &spec, dial.bypass_mode_downgrade)
            .await;
        debug!(
            uplink = %spec.name,
            wire = spec.wire,
            mode = %mode,
            ack_prefix_requested = dial.ack_prefix_requested,
            bypass_mode_downgrade = dial.bypass_mode_downgrade,
            "no warm-standby TCP websocket available, dialing on-demand"
        );
        let url = spec.dial_url(crate::Plane::Tcp).ok_or_else(|| {
            anyhow!("uplink {} wire {} missing tcp dial URL", spec.name, spec.wire)
        })?;
        let started = Instant::now();
        // Session resumption is per-session, not per-uplink: `resume_request`
        // is whatever the *caller* owns (`None` on a fresh dial). The ID the
        // server issues for this carrier rides back on the `TransportStream`
        // (`issued_session_id()`) and is picked up by whoever takes ownership
        // of the stream — including the warm-standby pool, whose entries are
        // handed to a session that then owns their ID. Nothing is stashed in
        // a process-global slot, so a concurrent session can no longer
        // present an ID that was minted for somebody else.
        let ws = crate::dial::dial_in_uplink_scope(
            &candidate.uplink,
            connect_transport(
                TransportDialOptions::new(cache, url, mode, source)
                    .with_network(DialNetworkOptions {
                        fwmark: spec.fwmark,
                        ipv6_first: spec.ipv6_first,
                    })
                    .with_combined_ss_kind(spec.combined_ss_kind(SsPathKind::Tcp))
                    .with_resume(resume_options(&dial)),
            ),
        )
        .await
        .with_context(|| TransportOperation::Connect { target: format!("to {}", url) })?;
        // Attribution follows the wire that was actually dialed. Filing this
        // under the primary wire — which is what this function did while it
        // could only ever dial the primary — puts the loss verdict in a slot
        // that nothing reads once `active_wire` moves, and lets one carrier's
        // descent cap another's.
        self.register_carrier_loss_probe(
            candidate.index,
            spec.wire,
            TransportKind::Tcp,
            ws.loss_probe(),
        );
        // Feed the on-demand dial latency into the RTT EWMA so real
        // connection quality is reflected in routing scores, not just probe
        // ping/pong times.
        self.report_connection_latency_for_wire(
            candidate.index,
            TransportKind::Tcp,
            spec.wire,
            started.elapsed(),
        )
        .await;
        // Mirror a transport-level downgrade (host clamp via `ws_mode_cache`
        // or inline H3→H2/H1 fallback inside `connect_transport`)
        // into the per-uplink `mode_downgrade_until` window. Without this,
        // `effective_tcp_mode` keeps reporting H3 while every actual dial
        // is silently clamped to H2 — the "ss/ws/h3 stays put" symptom.
        if let Some(requested) = ws.downgraded_from() {
            self.note_silent_transport_fallback_for_wire(
                candidate.index,
                TransportKind::Tcp,
                spec.wire,
                requested,
            );
        }
        Ok(ws)
    }

    pub async fn acquire_tcp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<TransportStream> {
        if let Some(ws) = self.try_take_tcp_standby(candidate).await {
            return Ok(ws);
        }
        self.connect_tcp_ws_fresh(candidate, source).await
    }

    /// [`Self::acquire_udp_standby_or_connect_with_store`] against the
    /// process-wide resume caches — the shape every caller had before per-carrier
    /// resume slots existed.
    pub async fn acquire_udp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
    ) -> Result<UdpSessionTransport> {
        self.acquire_udp_standby_or_connect_with_store(
            candidate,
            source,
            &outline_transport::UdpResumeStore::ProcessWide,
        )
        .await
    }

    /// Acquire a UDP carrier for `candidate`'s primary wire, keeping its
    /// Session IDs in `resume_store`. The shape every pre-existing caller
    /// gets; see [`Self::acquire_udp_on_wire`] for the wire-aware entry
    /// point.
    ///
    /// The store is what decides *whose* id this dial presents. Under
    /// [`UdpResumeStore::ProcessWide`](outline_transport::UdpResumeStore::ProcessWide)
    /// the SS-UDP slot is one per scope, so a caller that dials a carrier per
    /// flow presents whatever the previous flow parked — a hit on another
    /// session, not a missed resume. Callers with one carrier per flow pass a
    /// private store; see that type's documentation.
    pub async fn acquire_udp_standby_or_connect_with_store(
        &self,
        candidate: &UplinkCandidate,
        source: &'static str,
        resume_store: &outline_transport::UdpResumeStore,
    ) -> Result<UdpSessionTransport> {
        self.acquire_udp_on_wire(candidate, 0, source, resume_store).await
    }

    /// Acquire a UDP carrier on `wire`, keeping its Session IDs in
    /// `resume_store`. `wire = 0` is the primary carrier and reproduces the
    /// behaviour every existing caller has.
    ///
    /// Built from [`WireSpec`](crate::WireSpec) rather than `candidate.uplink`
    /// directly, so a VLESS fallback wire is just as dialable as an SS one —
    /// the QUIC mux used to be built out of the parent uplink's fields, which
    /// meant a fallback wire could only ever be SS. On a fleet whose primary
    /// *and* first fallback are both VLESS that left the UDP plane with no
    /// usable fallback at all.
    pub async fn acquire_udp_on_wire(
        &self,
        candidate: &UplinkCandidate,
        wire: u8,
        source: &'static str,
        resume_store: &outline_transport::UdpResumeStore,
    ) -> Result<UdpSessionTransport> {
        use outline_transport::UplinkConnectionBinding;
        let spec = crate::WireSpec::of(&candidate.uplink, wire)
            .ok_or_else(|| anyhow!("uplink {} has no wire {}", candidate.uplink.name, wire))?;
        let cache = self.inner.dns_cache.as_ref();
        // Per-uplink attribution for the open-connection gauge / close-time
        // classification counter. Built once per dial because every code path
        // below ends in a transport that owns its own `_lifetime` guard
        // attached via `with_uplink_binding`.
        let binding =
            || UplinkConnectionBinding::new(self.inner.group_name.as_str(), "udp", spec.name);
        if spec.transport == UplinkTransport::Vless {
            // VLESS UDP has no warm-standby pool — each destination opens its
            // own session inside the mux on first packet, so there is no
            // single pre-dialed stream to hand out up front.
            metrics::record_warm_standby_acquire("udp", &self.inner.group_name, spec.name, "miss");
            let udp_ws_url = spec.dial_url(crate::Plane::Udp).ok_or_else(|| {
                anyhow!(
                    "vless dial URL is not configured for uplink {} wire {}",
                    spec.name,
                    spec.wire
                )
            })?;
            let uuid = spec.vless_id.ok_or_else(|| {
                anyhow!("uplink {} wire {} is VLESS but has no vless_id", spec.name, spec.wire)
            })?;
            let mode = self.effective_udp_mode_for_wire(candidate.index, spec.wire).await;
            // Hook fired the first time the mux observes a transport-level
            // H3→H2/H1 downgrade on a per-target dial. The mux latches on
            // the first call so a burst of fresh sessions during the same
            // outage doesn't spam the uplink-manager. Mirrors the QUIC-mux
            // `on_fallback` wiring above so both pivots flow through the
            // same per-uplink `mode_downgrade_until` window.
            //
            // The wire is captured here, not read at fire time: the
            // notification lands well after this call returns, once the mux
            // has actually observed a per-target dial, so the closure is the
            // only place that still knows which wire it was building.
            let manager = self.clone();
            let index = candidate.index;
            let downgrade_wire = spec.wire;
            let on_downgrade: outline_transport::VlessUdpDowngradeNotifier =
                Arc::new(move |requested: outline_transport::TransportMode| {
                    manager.note_silent_transport_fallback_for_wire(
                        index,
                        TransportKind::Udp,
                        downgrade_wire,
                        requested,
                    );
                });
            // VLESS-UDP is dialed lazily per destination, so there is no
            // single carrier to register when the mux is built — the mux has
            // to hand each one over as it appears. Without this the whole UDP
            // plane of a VLESS uplink is unmeasured, which on a VLESS-only
            // fleet is where nearly all the traffic lives. Same wire-capture
            // reasoning as `on_downgrade` above: a wire-2 mux must file its
            // probe under wire 2, never under wire 0's slot.
            let probe_manager = self.clone();
            let probe_index = candidate.index;
            let probe_wire = spec.wire;
            let on_carrier: outline_transport::VlessUdpCarrierNotifier =
                Arc::new(move |probe: Option<outline_transport::CarrierLossProbe>| {
                    probe_manager.register_carrier_loss_probe(
                        probe_index,
                        probe_wire,
                        TransportKind::Udp,
                        probe,
                    );
                });
            let mux = VlessUdpSessionMux::new_with_limits(
                Arc::clone(&self.inner.dns_cache),
                udp_ws_url.clone(),
                mode,
                uuid,
                spec.fwmark,
                spec.ipv6_first,
                source,
                self.inner.load_balancing.udp_ws_keepalive_interval,
                self.inner.load_balancing.vless_udp_mux_limits,
            )
            .with_on_downgrade(Some(on_downgrade))
            .with_on_carrier(Some(on_carrier))
            // Padding is configured per uplink, not per wire — read from the
            // parent, mirroring `dial_in_uplink_scope` on every other path.
            .with_padding_override(candidate.uplink.padding)
            .with_resume_scope(self.resume_scope(&candidate.uplink.name).to_string())
            .with_resume_store(resume_store.clone())
            .with_uplink_binding(binding());
            return Ok(UdpSessionTransport::Vless(mux));
        }

        // WS-pooled UDP: try to reuse a pooled stream first. `try_take_alive`
        // loops past zombie entries (e.g. underlying H2/H3 torn down after
        // pooling) so we never hand a dead transport to the caller.
        //
        // The pool is filled on the primary wire until Task 8 moves it onto
        // the active wire; a fallback-wire acquire must never be handed a
        // primary-wire stream, so this take is gated to `wire == 0`.
        if spec.wire == 0 {
            let ctx = self.standby_ctx(candidate.index, TransportKind::Udp).await;
            if let Some(ws) = ctx.try_take_alive(&candidate.uplink.name).await {
                // Same reason as the TCP take above: a carrier reused out of the
                // pool is never dialled, so without this it is never measured.
                self.register_carrier_loss_probe(
                    candidate.index,
                    spec.wire,
                    TransportKind::Udp,
                    ws.loss_probe(),
                );
                // A pooled stream was dialled as a fresh session by the refill loop,
                // so the server minted it an id and it is riding on the stream. Move
                // it into this carrier's store or the flow would have no id of its
                // own and could never migrate — the reused-standby path was the one
                // place a TUN UDP flow silently lost its resume identity.
                let pooled_resume_key =
                    resume_cache_key(self.resume_scope(&candidate.uplink.name), "udp");
                resume_store
                    .ss()
                    .store_if_issued(pooled_resume_key, ws.issued_session_id());
                // `from_websocket` reads the carrier padding at build time, which on
                // the hot path runs after the dial returns — outside any dial scope.
                // Wrap the build in the per-uplink padding scope so a padded uplink's
                // reused standby stream frames its datagrams (mirrors VLESS-UDP).
                let transport = crate::dial::with_uplink_padding_scope(&candidate.uplink, async {
                    UdpWsTransport::from_websocket(
                        ws,
                        spec.cipher,
                        spec.password,
                        source,
                        self.inner.load_balancing.udp_ws_keepalive_interval,
                    )
                })
                .await?;
                return Ok(UdpSessionTransport::Ss(transport.with_uplink_binding(binding())));
            }
        }

        metrics::record_warm_standby_acquire("udp", &self.inner.group_name, spec.name, "miss");
        debug!(
            uplink = %spec.name,
            wire = spec.wire,
            "no warm-standby UDP websocket available, dialing on-demand"
        );
        // Combined-SS-aware: `dial_url()` resolves to `ss_xhttp_url`/
        // `ss_ws_url` on a combined wire (split `udp_url` is None there).
        let udp_ws_url = spec.dial_url(crate::Plane::Udp).ok_or_else(|| {
            anyhow!("no udp dial URL configured for uplink {} wire {}", spec.name, spec.wire)
        })?;
        let mode = self.effective_udp_mode_for_wire(candidate.index, spec.wire).await;
        let started = Instant::now();
        // Cross-transport session resumption for SS-UDP-over-WS.
        // Mirrors the TCP path's ResumeCache wiring; the cache key
        // distinguishes TCP and UDP slots so a TCP-side reconnect
        // doesn't steal the UDP-side Session ID and vice versa.
        let udp_resume_key = resume_cache_key(self.resume_scope(&candidate.uplink.name), "udp");
        let udp_resume_request = resume_store.ss().get(&udp_resume_key);
        // Scope the per-uplink padding override over the dial + build: padding
        // is read when `from_websocket` builds the transport (after the dial
        // returns), so the scope must wrap the whole future. raw QUIC (handled
        // above) and the global default are unaffected by an absent override.
        let connect = UdpWsTransport::connect_with_resume(
            cache,
            udp_ws_url,
            mode,
            spec.cipher,
            spec.password,
            spec.fwmark,
            spec.ipv6_first,
            source,
            self.inner.load_balancing.udp_ws_keepalive_interval,
            udp_resume_request,
            spec.combined_ss_kind(SsPathKind::Udp),
        );
        let (transport, udp_issued, udp_downgraded_from) =
            crate::dial::with_uplink_padding_scope(&candidate.uplink, connect)
                .await
                .with_context(|| TransportOperation::Connect {
                    target: format!("to {}", udp_ws_url),
                })?;
        resume_store.ss().store_if_issued(udp_resume_key, udp_issued);
        // Attribution follows the wire that was actually dialed — see the TCP
        // twin (`connect_tcp_ws_fresh_internal`) for why filing this under
        // the primary wire unconditionally puts the loss verdict in a slot
        // nothing reads once `active_wire` moves, and lets one carrier's
        // descent cap another's.
        self.register_carrier_loss_probe(
            candidate.index,
            spec.wire,
            TransportKind::Udp,
            transport.loss_probe(),
        );
        self.report_connection_latency_for_wire(
            candidate.index,
            TransportKind::Udp,
            spec.wire,
            started.elapsed(),
        )
        .await;
        // Mirror a transport-level downgrade (host clamp via `ws_mode_cache`
        // or inline H3→H2/H1 fallback) into the per-uplink window so
        // `effective_udp_mode_for_wire` reflects reality on subsequent dials.
        if let Some(requested) = udp_downgraded_from {
            self.note_silent_transport_fallback_for_wire(
                candidate.index,
                TransportKind::Udp,
                spec.wire,
                requested,
            );
        }
        Ok(UdpSessionTransport::Ss(transport.with_uplink_binding(binding())))
    }

    pub(crate) async fn refill_all_standby(&self) {
        for index in 0..self.inner.uplinks.len() {
            // Administratively-disabled uplinks (operator on/off) are kept out
            // of every automatic path: do not open or maintain warm-standby
            // sockets to a server the operator parked.
            if !self.inner.admin_enabled(index) {
                continue;
            }
            self.maintain_pool(index, TransportKind::Tcp).await;
            self.maintain_pool(index, TransportKind::Udp).await;
        }
    }

    /// Queue a background refill of the `(index, transport)` pool, coalescing
    /// with a refill that is already queued.
    ///
    /// Callers on the take path fire this once per acquisition, but several
    /// sessions can acquire from the same pool at once; without the gate each of
    /// them spawned a task that resolved the standby context (itself a status
    /// read), took the refill mutex, saw the pool back at `desired` and exited.
    /// The gate collapses that burst into one task — see [`RefillGate`] for why
    /// the claim is released before the work rather than after.
    pub(crate) fn spawn_refill(&self, index: usize, transport: TransportKind) {
        if !self.inner.standby_pools[index].refill_gate(transport).try_claim() {
            return;
        }
        let manager = self.clone();
        tokio::spawn(async move {
            manager.inner.standby_pools[index].refill_gate(transport).release();
            manager.refill_pool(index, transport).await;
        });
    }

    pub(crate) async fn maintain_pool(&self, index: usize, transport: TransportKind) {
        let ctx = self.standby_ctx(index, transport).await;
        ctx.validate().await;
        ctx.refill().await;
    }

    /// Sends WebSocket ping frames on idle TCP standby sockets so middleboxes
    /// keep the connection state warm, then replenishes any entries that were
    /// dropped as stale.
    pub(crate) async fn keepalive_tcp_pool(&self, index: usize) {
        if self.inner.load_balancing.warm_standby_tcp == 0 {
            return;
        }
        let ctx = self.standby_ctx(index, TransportKind::Tcp).await;
        if !matches!(ctx.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless) {
            return;
        }
        ctx.keepalive().await;
        ctx.refill().await;
    }

    async fn refill_pool(&self, index: usize, transport: TransportKind) {
        let ctx = self.standby_ctx(index, transport).await;
        ctx.refill().await;
    }

    pub(crate) async fn clear_standby(&self, index: usize, transport: TransportKind) {
        let pool = &self.inner.standby_pools[index];
        let deque = match transport {
            TransportKind::Tcp => &pool.tcp,
            TransportKind::Udp => &pool.udp,
        };
        let mut guard = deque.lock().await;
        guard.clear();
        maybe_shrink_vecdeque(&mut guard);
    }

    pub fn spawn_warm_standby_loop(&self) {
        if self.inner.load_balancing.warm_standby_tcp == 0
            && self.inner.load_balancing.warm_standby_udp == 0
        {
            return;
        }

        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        tokio::spawn(async move {
            manager.refill_all_standby().await;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(WARM_STANDBY_MAINTENANCE_INTERVAL) => {}
                }
                manager.refill_all_standby().await;
            }
        });
    }

    /// Spawns a background loop that pings warm-standby **TCP** pool
    /// connections at `tcp_ws_standby_keepalive_interval` to keep them alive
    /// through NAT/firewall idle-timeout windows.  This is separate from the
    /// 15-second validation loop: the validation loop also runs for UDP and
    /// handles refill; this loop is TCP-only and intentionally runs more
    /// frequently.
    pub fn spawn_standby_keepalive_loop(&self) {
        let interval = match self.inner.load_balancing.tcp_ws_standby_keepalive_interval {
            Some(d) if self.inner.load_balancing.warm_standby_tcp > 0 => d,
            _ => return,
        };

        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(interval) => {}
                }
                for index in 0..manager.inner.uplinks.len() {
                    if !manager.inner.admin_enabled(index) {
                        continue;
                    }
                    manager.keepalive_tcp_pool(index).await;
                }
            }
        });
    }

    pub async fn run_standby_maintenance(&self) {
        self.refill_all_standby().await;
    }

    #[cfg(test)]
    pub(crate) async fn run_tcp_standby_keepalive(&self, index: usize) {
        self.keepalive_tcp_pool(index).await;
    }
}
