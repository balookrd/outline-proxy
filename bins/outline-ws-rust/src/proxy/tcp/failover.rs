use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use tracing::debug;

use outline_transport::{
    SessionId, TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, TcpWriter,
    UplinkConnectionBinding, UpstreamTransportGuard,
};
use outline_uplink::{
    TransportKind, UplinkCandidate, UplinkManager, UplinkTransport, WireAttempt, WireSpec,
};
use socks5_proto::TargetAddr;

pub(super) const MAX_CHUNK0_FAILOVER_BUF: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TcpUplinkSource {
    Standby,
    FreshDial,
}

pub(super) struct ConnectedTcpUplink {
    pub(super) writer: TcpWriter,
    pub(super) reader: TcpReader,
    pub(super) source: TcpUplinkSource,
    /// Which wire of the parent uplink this connection rides. `0` means
    /// primary; `1..=N` means `fallbacks[wire_index - 1]`. Carried through
    /// to [`ActiveTcpUplink`] so the chunk-0 failover step can attempt
    /// other wires of the same uplink before jumping to a different one.
    pub(super) wire_index: u8,
    /// The Session ID the server minted **for this session** on this
    /// carrier (`X-Outline-Session` on the upgrade response), if the
    /// server has resumption enabled. `None` on direct-socket / non-WS
    /// carriers and against servers without resumption.
    ///
    /// This ID belongs to the session, not to the uplink: only a redial
    /// of *this* session may present it back as `X-Outline-Resume`. A
    /// fresh dial always presents nothing — on a resume hit the server
    /// ignores the handshake target and re-attaches the parked upstream,
    /// so replaying somebody else's ID would silently connect this
    /// session to the wrong destination.
    pub(super) session_id: Option<SessionId>,
}

/// All mutable state that tracks the currently-active uplink during the
/// chunk-0 failover loop.  Consolidates what were previously five separate
/// local variables (`active_candidate`, `active_uplink_name`, `active_index`,
/// `active_source`, plus the `writer`/`reader` pair).  Keeping them together
/// makes it impossible to forget a field when switching to a new uplink.
pub(super) struct ActiveTcpUplink {
    pub(super) index: usize,
    /// Cheap to clone across closure boundaries — no per-failover String alloc.
    pub(super) name: Arc<str>,
    /// Retained for standby-socket fresh-dial retries during phase 1.
    pub(super) candidate: UplinkCandidate,
    pub(super) writer: TcpWriter,
    pub(super) reader: TcpReader,
    pub(super) source: TcpUplinkSource,
    /// Which wire of `candidate.uplink` this connection rides
    /// (`[primary, fallbacks[0], fallbacks[1], ...]`). Used by chunk-0
    /// failover to avoid retrying the wire that just stalled and to
    /// know which wires of this same uplink remain to try before
    /// jumping to a different uplink.
    pub(super) wire_index: u8,
    /// Session ID this session was issued on its current carrier — see
    /// [`ConnectedTcpUplink::session_id`]. Every chunk-0 failover step
    /// replaces the carrier and therefore the ID; the pinned relay picks
    /// the final value up and owns it for the rest of the session.
    pub(super) session_id: Option<SessionId>,
}

impl ActiveTcpUplink {
    pub(super) fn new(candidate: UplinkCandidate, connected: ConnectedTcpUplink) -> Self {
        Self {
            index: candidate.index,
            name: Arc::from(candidate.uplink.name.as_str()),
            candidate,
            writer: connected.writer,
            reader: connected.reader,
            source: connected.source,
            wire_index: connected.wire_index,
            session_id: connected.session_id,
        }
    }

    /// Switch to a new uplink after a successful failover connection.
    /// All fields are updated atomically — partial updates are impossible.
    pub(super) fn switch_to(
        &mut self,
        next_candidate: UplinkCandidate,
        reconnected: ConnectedTcpUplink,
    ) {
        self.index = next_candidate.index;
        self.name = Arc::from(next_candidate.uplink.name.as_str());
        self.candidate = next_candidate;
        self.writer = reconnected.writer;
        self.reader = reconnected.reader;
        self.source = reconnected.source;
        self.wire_index = reconnected.wire_index;
        self.session_id = reconnected.session_id;
    }

    /// Replace only the transport (writer/reader/source) while keeping the
    /// same uplink identity.  Used when a warm-standby socket proves stale
    /// and we retry the same uplink with a fresh dial.
    pub(super) fn replace_transport(&mut self, reconnected: ConnectedTcpUplink) {
        self.writer = reconnected.writer;
        self.reader = reconnected.reader;
        self.source = reconnected.source;
        self.wire_index = reconnected.wire_index;
        self.session_id = reconnected.session_id;
    }

    /// Replace the transport with a fresh dial of a *different* wire on
    /// the same uplink. Updates `wire_index` and the io halves; uplink
    /// identity (`index`, `name`, `candidate`) stays put. Used by the
    /// wire-aware chunk-0 failover path.
    pub(super) fn replace_wire(&mut self, reconnected: ConnectedTcpUplink) {
        self.writer = reconnected.writer;
        self.reader = reconnected.reader;
        self.source = reconnected.source;
        self.wire_index = reconnected.wire_index;
        self.session_id = reconnected.session_id;
    }
}

/// Dials a TCP uplink and, when the primary transport fails, transparently
/// retries each configured `[[outline.uplinks.fallbacks]]` entry on the same
/// uplink before propagating the error to the cross-uplink failover loop.
///
/// The primary error is surfaced via `anyhow::Error::context` chaining when
/// every fallback has also failed; a successful fallback returns an opaque
/// `ConnectedTcpUplink` indistinguishable from a primary success.
///
/// Per-fallback dial errors are logged at warn-level (so an operator can see
/// which wire took us down to the next fallback) but are not surfaced as a
/// `report_runtime_failure` against the parent uplink — the parent's runtime-
/// failure counter is bumped only by the *outer* dial loop and only when
/// every wire on this uplink (primary + all fallbacks) has been exhausted.
pub(super) async fn connect_tcp_uplink(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<ConnectedTcpUplink> {
    // Scope the per-uplink padding override over the whole dial + build. The
    // transport reads `effective_carrier_padding` when it splits/spawns the
    // writer (`do_tcp_ss_setup` / `vless_tcp_pair_from_ws`), which runs AFTER
    // the dial future returns — so the scope must wrap this entire call, not
    // just the dial (the manager's `dial_in_uplink_scope` covers only the dial,
    // which is enough for the TLS fingerprint but not for padding).
    let mut connected = outline_uplink::dial::with_uplink_padding_scope(
        &candidate.uplink,
        connect_tcp_uplink_inner(uplinks, candidate, target),
    )
    .await?;
    // Install the carrier control-signal handler so a server downstream-throttle
    // notice on this carrier penalises the uplink and migrates traffic away.
    // No-op (handle is `None`) unless the client opted in; ignored by every
    // non-VLESS-over-WS reader.
    if let Some(handle) =
        outline_uplink::dial::throttle_handle(uplinks, candidate.index, TransportKind::Tcp)
    {
        connected.reader = connected.reader.with_throttle_handle(handle);
    }
    Ok(connected)
}

async fn connect_tcp_uplink_inner(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<ConnectedTcpUplink> {
    // `allow_fallbacks: true` unconditionally — SOCKS has walked its full wire
    // chain for as long as the chain has existed, unlike the TUN ingress whose
    // wire support is new enough to need `tun_wire_dial` gating.
    let (connected, wire) = uplinks
        .dial_over_wires(candidate, TransportKind::Tcp, true, |wire| async move {
            if wire == 0 {
                // The pool (and its own standby/fresh-dial fallback) only ever
                // serves the primary wire.
                return connect_tcp_uplink_primary(uplinks, candidate, target)
                    .await
                    .map(WireAttempt::Built);
            }
            let spec = WireSpec::of(&candidate.uplink, wire)
                .ok_or_else(|| anyhow!("uplink {} has no wire {wire}", candidate.uplink.name))?;
            // A fresh fallback dial never presents a Session ID — this is the
            // initial dial loop, there is no prior session to resume.
            record_tcp_resume_lookup(uplinks, None);
            let ws = uplinks
                .connect_tcp_ws_fresh_on_wire(candidate, wire, "socks_tcp_fb")
                .await?;
            let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
            let binding = tcp_binding(uplinks, spec.name);
            // Capture before `do_tcp_ss_setup` takes ownership of the stream.
            let session_id = ws.issued_session_id();
            let (writer, reader) = do_tcp_ss_setup(
                ws,
                &spec,
                target,
                "socks_tcp_fb",
                keepalive_interval,
                binding,
                false,
            )
            .await?;
            Ok(WireAttempt::Built(ConnectedTcpUplink {
                writer,
                reader,
                source: TcpUplinkSource::FreshDial,
                wire_index: wire,
                session_id,
            }))
        })
        .await?;

    if wire != 0 {
        outline_metrics::record_uplink_selected(
            "tcp",
            uplinks.group_name(),
            &candidate.uplink.name,
        );
        debug!(
            uplink = %candidate.uplink.name,
            target = %target,
            wire_index = wire,
            "TCP fallback wire dial succeeded",
        );
    }
    Ok(connected)
}

/// Dial a specific wire on `candidate` — primary if `wire_index == 0`,
/// `fallbacks[wire_index - 1]` otherwise. Used by the wire-aware chunk-0
/// failover step to retry a different wire of the same uplink before
/// falling through to a different uplink. Distinct from
/// [`connect_tcp_uplink`] which iterates wires internally and picks the
/// first one to succeed; the chunk-0 failover loop already knows which
/// wire just failed and wants to skip it.
///
/// No resume id is presented here, unlike [`connect_tcp_specific_wire_fresh`]:
/// `wire_index == 0` is served from the warm-standby pool, and a pooled socket
/// already completed its upgrade under its *own* Session ID. Resume is a
/// property of the handshake, so it can only be requested by a dial we make
/// ourselves.
pub(super) async fn connect_tcp_specific_wire(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    wire_index: u8,
) -> Result<ConnectedTcpUplink> {
    // Padding scope wraps the dial + transport build (see `connect_tcp_uplink`).
    outline_uplink::dial::with_uplink_padding_scope(&candidate.uplink, async move {
        if wire_index == 0 {
            return connect_tcp_uplink_primary(uplinks, candidate, target).await;
        }
        let spec = WireSpec::of(&candidate.uplink, wire_index)
            .ok_or_else(|| anyhow!("uplink {} has no wire {wire_index}", candidate.uplink.name))?;
        // A fresh wire-handover dial never presents a Session ID — see this
        // function's doc.
        record_tcp_resume_lookup(uplinks, None);
        let ws = uplinks
            .connect_tcp_ws_fresh_on_wire(candidate, wire_index, "socks_tcp_fb")
            .await?;
        let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
        let binding = tcp_binding(uplinks, spec.name);
        let session_id = ws.issued_session_id();
        let (writer, reader) =
            do_tcp_ss_setup(ws, &spec, target, "socks_tcp_fb", keepalive_interval, binding, false)
                .await?;
        Ok(ConnectedTcpUplink {
            writer,
            reader,
            source: TcpUplinkSource::FreshDial,
            wire_index,
            session_id,
        })
    })
    .await
}

/// Dial a specific wire on `candidate` *bypassing* the warm-standby pool —
/// always a fresh on-demand dial of `wire_index`. Used by same-uplink
/// recovery paths in `connect/retry.rs` where the prior socket has just
/// failed (warm-standby stale, chunk-0 WS reset). Distinct from
/// [`connect_tcp_specific_wire`] which goes through the standby pool on
/// `wire_index == 0` — that would be wrong here because the wire that just
/// failed may have a stale standby socket queued.
///
/// Because every wire here is dialled fresh, the session's own `resume_request`
/// can be presented: on a hit the server re-attaches the upstream it parked
/// when the previous carrier died, so the handover does not reopen the
/// connection to the destination.
pub(super) async fn connect_tcp_specific_wire_fresh(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    wire_index: u8,
    resume_request: Option<SessionId>,
) -> Result<ConnectedTcpUplink> {
    // Padding scope wraps the dial + transport build (see `connect_tcp_uplink`).
    outline_uplink::dial::with_uplink_padding_scope(&candidate.uplink, async move {
        if wire_index == 0 {
            return connect_tcp_uplink_fresh(uplinks, candidate, target, resume_request).await;
        }
        let spec = WireSpec::of(&candidate.uplink, wire_index)
            .ok_or_else(|| anyhow!("uplink {} has no wire {wire_index}", candidate.uplink.name))?;
        record_tcp_resume_lookup(uplinks, resume_request);
        let ws = uplinks
            .connect_tcp_ws_redial_on_wire(candidate, wire_index, "socks_tcp_fb", resume_request)
            .await?;
        let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
        let binding = tcp_binding(uplinks, spec.name);
        let session_id = ws.issued_session_id();
        let (writer, reader) = do_tcp_ss_setup(
            ws,
            &spec,
            target,
            "socks_tcp_fb",
            keepalive_interval,
            binding,
            resume_request.is_some(),
        )
        .await?;
        Ok(ConnectedTcpUplink {
            writer,
            reader,
            source: TcpUplinkSource::FreshDial,
            wire_index,
            session_id,
        })
    })
    .await
}

async fn connect_tcp_uplink_primary(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<ConnectedTcpUplink> {
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate, 0).await {
        let spec = WireSpec::from_uplink(&candidate.uplink);
        let binding = tcp_binding(uplinks, spec.name);
        // Read the ID off the stream *before* `do_tcp_ss_setup` consumes it:
        // a pooled standby carrier was dialed fresh (no resume request), so
        // the ID the server minted for it now belongs to this session.
        let session_id = ws.issued_session_id();
        // A pooled carrier was dialed by the refill loop with no id of its own.
        match do_tcp_ss_setup(ws, &spec, target, "socks_tcp", keepalive_interval, binding, false)
            .await
        {
            Ok((writer, reader)) => {
                return Ok(ConnectedTcpUplink {
                    writer,
                    reader,
                    source: TcpUplinkSource::Standby,
                    wire_index: 0,
                    session_id,
                });
            },
            Err(e) => {
                debug!(
                    uplink = %candidate.uplink.name,
                    error = %format!("{e:#}"),
                    "stale standby TCP pool connection, retrying with fresh dial"
                );
            },
        }
    }

    // Initial dial of a brand-new session — no prior Session ID to present.
    connect_tcp_uplink_fresh(uplinks, candidate, target, None).await
}

/// `resume_request` is this session's own Session ID when the caller is
/// re-dialing a session that already exists (chunk-0 wire handover, retry after
/// a stale standby socket), and `None` for a brand-new session. Presenting it
/// lets the server re-attach a still-parked upstream rather than open a fresh
/// connection to the destination.
pub(super) async fn connect_tcp_uplink_fresh(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    resume_request: Option<SessionId>,
) -> Result<ConnectedTcpUplink> {
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
    let ws = uplinks
        .connect_tcp_ws_redial(candidate, "socks_tcp", resume_request)
        .await?;
    let spec = WireSpec::from_uplink(&candidate.uplink);
    let binding = tcp_binding(uplinks, spec.name);
    // Capture before `do_tcp_ss_setup` takes ownership of the stream.
    let session_id = ws.issued_session_id();
    let (writer, reader) = do_tcp_ss_setup(
        ws,
        &spec,
        target,
        "socks_tcp",
        keepalive_interval,
        binding,
        resume_request.is_some(),
    )
    .await?;
    Ok(ConnectedTcpUplink {
        writer,
        reader,
        source: TcpUplinkSource::FreshDial,
        wire_index: 0,
        session_id,
    })
}

/// Re-dial a TCP WebSocket session for the mid-session retry path
/// after a transport reset. Identical to [`connect_tcp_uplink_fresh`]
/// at its WS branch with one restriction and one opt-in:
///
/// * WS-family carriers only (`UplinkTransport::Ss` for SS-WS,
///   `UplinkTransport::Vless` for VLESS-WS). raw-QUIC has no
///   Ack-Prefix support in v1.1; the orchestrator degrades to
///   "no retry" for those uplinks rather than redialling a path
///   that would not give us the offset header.
/// * No raw-QUIC fallback — even when the uplink is configured for
///   QUIC, mid-session retry only operates on the WS dial path.
/// * Advertises `X-Outline-Resume-Ack-Prefix: 1` so the server emits
///   the v1 control frame and the reader can park `up_acked`.
/// * Asks for the wire's **configured** carrier, not its mode-downgrade
///   cap — the carrier this dial lands on is the one the rescued session
///   rides for the rest of its life, and the cap is usually a reading of
///   the very carrier death being recovered from. See
///   [`UplinkManager::connect_tcp_ws_migrate_with_ack_prefix`].
///
/// `wire_index` selects which wire of `candidate` to redial: `0` is the
/// primary, `1..=N` map to `fallbacks[wire_index - 1]`. The caller
/// (mid-session retry orchestrator) reads `uplinks.active_wire(...)`
/// just before the redial so a session that established on a fallback
/// (because primary is currently dead) retries on the same fallback
/// instead of slamming a known-dead primary URL and ballooning the
/// parent uplink's runtime-failure streak.
///
/// `resume_request` is the Session ID **this session** was issued on the
/// carrier that just died (`ConnectedTcpUplink::session_id`), or `None`
/// if it never got one. It is passed in explicitly — never looked up in
/// a shared cache — because a resume hit re-attaches whatever upstream
/// is parked under the ID, so presenting another session's ID would
/// hand this session the wrong destination.
///
/// Returns the fresh `(TcpWriter, TcpReader)` ready for replay; the
/// caller is responsible for inspecting `reader.upstream_acked_offset()`
/// and pushing replay bytes through the writer before resuming the
/// relay.
pub(super) async fn redial_for_mid_session_retry(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    wire_index: u8,
    symmetric_replay_enabled: bool,
    client_acked_offset: u64,
    resume_request: Option<SessionId>,
) -> Result<ConnectedTcpUplink> {
    // Padding scope wraps the dial + transport build (see `connect_tcp_uplink`).
    outline_uplink::dial::with_uplink_padding_scope(
        &candidate.uplink,
        redial_for_mid_session_retry_inner(
            uplinks,
            candidate,
            target,
            wire_index,
            symmetric_replay_enabled,
            client_acked_offset,
            resume_request,
        ),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn redial_for_mid_session_retry_inner(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    wire_index: u8,
    // v2 Symmetric Downlink Replay parameters. When
    // `symmetric_replay_enabled` is `true`, the redial advertises
    // `X-Outline-Resume-Symmetric-Replay: 1` and reports
    // `client_acked_offset` via the
    // `X-Outline-Resume-Down-Acked` request header so the server can
    // emit a precise downlink replay slice on the resume hit.
    symmetric_replay_enabled: bool,
    client_acked_offset: u64,
    // This session's own Session ID, presented as `X-Outline-Resume`.
    resume_request: Option<SessionId>,
) -> Result<ConnectedTcpUplink> {
    if wire_index == 0 {
        if !matches!(candidate.uplink.transport, UplinkTransport::Ss | UplinkTransport::Vless,) {
            bail!(
                "mid-session retry redial only supports WS-family uplinks (SS-WS or \
                 VLESS-WS); uplink {} primary uses transport {:?}",
                candidate.uplink.name,
                candidate.uplink.transport,
            );
        }
        let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
        record_tcp_resume_lookup(uplinks, resume_request);
        // The migrate-* dials ask for the uplink's *configured* carrier rather
        // than the capped one — see `connect_tcp_ws_migrate_with_ack_prefix`.
        // A retry is triggered by a carrier death, and that death caps the
        // uplink one rank down (`ws_h3` → `ws_h2`) for `mode_downgrade_secs`:
        // not from this session (it reports its runtime failure only once the
        // relay loop is done, so a retry that succeeds never reports one), but
        // from every other party watching the same carrier — the standby refill
        // loop, a TUN flow on the same manager, a sibling session whose own
        // retry failed, the probe loop. A shared H3 carrier dies for all of
        // them at once, so by the time this redial runs the cap is usually
        // already installed, and honouring it would pin the rescued session to
        // TCP-over-TCP for the rest of its life (nothing migrates a live
        // session back up).
        let ws = if symmetric_replay_enabled {
            uplinks
                .connect_tcp_ws_migrate_with_symmetric_replay(
                    candidate,
                    "socks_tcp_retry",
                    resume_request,
                    client_acked_offset,
                )
                .await?
        } else {
            uplinks
                .connect_tcp_ws_migrate_with_ack_prefix(
                    candidate,
                    "socks_tcp_retry",
                    resume_request,
                )
                .await?
        };
        let spec = WireSpec::from_uplink(&candidate.uplink);
        let binding = tcp_binding(uplinks, spec.name);
        // The server mints a new ID on the resume hit too — capture it before
        // the stream is consumed so the session can redial again later.
        let session_id = ws.issued_session_id();
        let (writer, reader) = do_tcp_ss_setup(
            ws,
            &spec,
            target,
            "socks_tcp_retry",
            keepalive_interval,
            binding,
            resume_request.is_some(),
        )
        .await?;
        return Ok(ConnectedTcpUplink {
            writer,
            reader,
            source: TcpUplinkSource::FreshDial,
            wire_index: 0,
            session_id,
        });
    }

    // Fallback-wire path: dial `fallbacks[wire_index - 1]` with the same
    // Ack-Prefix / Symmetric Downlink Replay options the primary-wire
    // path advertises.  Without this branch, mid-session retry on a
    // session that lives on a fallback wire would always slam the
    // (often dead) primary URL — `redial_for_mid_session_retry`'s
    // previous behaviour — and the resulting redial failure would
    // bubble up into `report_runtime_failure` on the parent uplink,
    // flapping the whole uplink off the candidate set.
    let spec = WireSpec::of(&candidate.uplink, wire_index).ok_or_else(|| {
        anyhow!("mid-session retry: uplink {} has no wire {wire_index}", candidate.uplink.name)
    })?;
    if !spec.is_ws_family() {
        bail!(
            "mid-session retry redial only supports WS-family wires; uplink {} wire {} uses \
             transport {:?}",
            candidate.uplink.name,
            wire_index,
            spec.transport,
        );
    }
    record_tcp_resume_lookup(uplinks, resume_request);
    // Same reasoning as the primary-wire branch above: a session rescued onto
    // this wire keeps whatever carrier it lands on, so the retry asks for the
    // wire's configured one via the migrate-* dials, bypassing the per-wire
    // cap in `fallback_mode_downgrades[wire_index - 1]`.
    let ws = if symmetric_replay_enabled {
        uplinks
            .connect_tcp_ws_migrate_with_symmetric_replay_on_wire(
                candidate,
                wire_index,
                "socks_tcp_retry",
                resume_request,
                client_acked_offset,
            )
            .await?
    } else {
        uplinks
            .connect_tcp_ws_migrate_with_ack_prefix_on_wire(
                candidate,
                wire_index,
                "socks_tcp_retry",
                resume_request,
            )
            .await?
    };
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
    let binding = tcp_binding(uplinks, spec.name);
    let session_id = ws.issued_session_id();
    let (writer, reader) = do_tcp_ss_setup(
        ws,
        &spec,
        target,
        "socks_tcp_retry",
        keepalive_interval,
        binding,
        resume_request.is_some(),
    )
    .await?;
    Ok(ConnectedTcpUplink {
        writer,
        reader,
        source: TcpUplinkSource::FreshDial,
        wire_index,
        session_id,
    })
}

/// Records the resume-lookup outcome for a TCP dial: a `hit` is a redial that
/// carries the session's own Session ID, a `miss` is a dial with nothing to
/// present (fresh session, or a session the server never issued an ID for).
///
/// Reported per group when the group shares one resume scope (a mesh cluster,
/// `shared_resume`), else per uplink — the label mirrors what the resume id
/// actually spans.
fn record_tcp_resume_lookup(uplinks: &UplinkManager, resume_request: Option<SessionId>) {
    outline_metrics::record_resume_lookup(
        "tcp",
        if uplinks.shared_resume() { "group" } else { "uplink" },
        if resume_request.is_some() { "hit" } else { "miss" },
    );
}

/// Build the per-connection uplink-attribution tag used by
/// `UpstreamTransportGuard::Drop` to maintain the open-connection gauge and
/// classify the close against the currently-active uplink. Lives here (not in
/// `outline-uplink`) because the binding is per-connection and only the
/// dispatch layer knows which group + uplink the connection actually rides.
fn tcp_binding(uplinks: &UplinkManager, uplink_name: &str) -> UplinkConnectionBinding {
    UplinkConnectionBinding::new(uplinks.group_name(), "tcp", uplink_name)
}

/// Whether this carrier may be preceded by the v1 `"ORSM"` / v2 `"ORDR"` resume
/// control frames.
///
/// Both conditions are load-bearing. The server echoes the capability bits to
/// anyone who advertises them, but emits the frames only after a resume **hit** —
/// which a dial carrying no Session ID cannot produce. Reading a frame that was
/// never sent consumes the first 14 bytes of real payload as a control header
/// and kills the session on the parse, so the echo alone must never arm the
/// reader. Mirrors the gate `outline_tun::tcp::engine::connect` applies.
fn expects_resume_control_frames(presented_resume_id: bool, advertised_by_server: bool) -> bool {
    presented_resume_id && advertised_by_server
}

async fn do_tcp_ss_setup(
    ws_stream: outline_transport::TransportStream,
    setup: &WireSpec<'_>,
    target: &TargetAddr,
    source: &'static str,
    keepalive_interval: Option<std::time::Duration>,
    binding: UplinkConnectionBinding,
    // Whether this dial presented a Session ID, i.e. whether a resume hit — and
    // therefore a control frame — was possible at all. See
    // [`expects_resume_control_frames`].
    presented_resume_id: bool,
) -> Result<(TcpWriter, TcpReader)> {
    let shared_conn_info = ws_stream.shared_connection_info();
    let lifetime = UpstreamTransportGuard::new_with_uplink(source, "tcp", binding);
    let diag = outline_transport::WsReadDiag {
        conn_id: shared_conn_info.map(|(id, _)| id),
        mode: shared_conn_info.map(|(_, m)| m).unwrap_or("h1"),
        is_h3: ws_stream.is_h3(),
        uplink: setup.name.to_string(),
        target: target.to_string(),
    };

    // Capture the negotiated Ack-Prefix bit before any consume —
    // both VLESS's `vless_tcp_pair_from_ws` and SS-WS's `.split()`
    // take ownership of the underlying stream halves, after which
    // the accessor on the enum is gone.
    //
    // A fresh dial advertises the capabilities too — that advertisement is what
    // makes the server allocate this session's downlink replay ring — so the
    // echo comes back on carriers that will never be sent a control frame. Only
    // a dial that presented an id can be.
    let expect_ack_prefix = expects_resume_control_frames(
        presented_resume_id,
        ws_stream.ack_prefix_advertised_by_server(),
    );
    let expect_downlink_replay = expects_resume_control_frames(
        presented_resume_id,
        ws_stream.symmetric_replay_advertised_by_server(),
    );

    if setup.transport == UplinkTransport::Vless {
        let uuid = setup
            .vless_id
            .as_ref()
            .ok_or_else(|| anyhow!("uplink {} missing vless_id", setup.name))?;
        let (writer, reader) = outline_transport::vless::vless_tcp_pair_from_ws(
            ws_stream,
            uuid,
            target,
            lifetime,
            diag,
            keepalive_interval,
        )?;
        debug!(
            uplink = %setup.name,
            target = %target,
            transport = "ws",
            protocol = "vless",
            "opened VLESS uplink"
        );
        let reader = TcpReader::Vless(reader)
            .with_expect_ack_prefix(expect_ack_prefix)
            .with_expect_downlink_replay(expect_downlink_replay);
        return Ok((TcpWriter::Vless(writer), reader));
    }

    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = setup.cipher.derive_master_key(setup.password)?;
    let (writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, setup.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let reader = TcpShadowsocksReader::new(ws_stream, setup.cipher, &master_key, lifetime, ctrl_tx);
    let mut writer = TcpWriter::Ws(writer);
    let reader = TcpReader::Ws(Box::new(reader))
        .with_request_salt(writer.request_salt())
        .with_diag(diag)
        .with_expect_ack_prefix(expect_ack_prefix)
        .with_expect_downlink_replay(expect_downlink_replay);
    send_initial_ss_target(&mut writer, setup, target, "ws").await?;
    Ok((writer, reader))
}

async fn send_initial_ss_target(
    writer: &mut TcpWriter,
    setup: &WireSpec<'_>,
    target: &TargetAddr,
    transport: &'static str,
) -> Result<()> {
    let target_wire = target.to_wire_bytes()?;
    writer
        .send_chunk(&target_wire)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %setup.name,
        target = %target,
        target_wire_len = target_wire.len(),
        transport = transport,
        ss2022 = setup.cipher.is_ss2022(),
        "sent initial Shadowsocks target header to uplink"
    );
    Ok(())
}

// Gated on `h3`: the test proves which carrier the retry dial asks for by
// watching for the QUIC Initial that only an `ws_h3` dial emits, which the
// dialer cannot produce without QUIC compiled in.
#[cfg(all(test, feature = "h3"))]
#[path = "tests/failover.rs"]
mod tests;
