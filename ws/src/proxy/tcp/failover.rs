use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tracing::{debug, warn};

use outline_transport::{
    TcpReader, TcpWriter,
    TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source, connect_websocket_with_resume,
    global_resume_cache,
};
use socks5_proto::TargetAddr;
use outline_uplink::{
    FallbackTransport, TransportKind, UplinkCandidate, UplinkManager, UplinkTransport,
};

pub(super) const MAX_CHUNK0_FAILOVER_BUF: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TcpUplinkSource {
    Standby,
    FreshDial,
    DirectSocket,
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
    }

    /// Replace only the transport (writer/reader/source) while keeping the
    /// same uplink identity.  Used when a warm-standby socket proves stale
    /// and we retry the same uplink with a fresh dial.
    pub(super) fn replace_transport(&mut self, reconnected: ConnectedTcpUplink) {
        self.writer = reconnected.writer;
        self.reader = reconnected.reader;
        self.source = reconnected.source;
        self.wire_index = reconnected.wire_index;
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
    let total_wires = 1 + candidate.uplink.fallbacks.len();
    let dial_order =
        uplinks.wire_dial_order(candidate.index, TransportKind::Tcp, total_wires);

    // Fast path: no fallbacks — preserve the previous error-propagation
    // semantics (no extra context wrapping when only the primary exists).
    if total_wires == 1 {
        return connect_tcp_uplink_primary(uplinks, candidate, target).await;
    }

    let mut last_err: Option<anyhow::Error> = None;
    for &wire_index in &dial_order {
        let attempt = if wire_index == 0 {
            connect_tcp_uplink_primary(uplinks, candidate, target).await
        } else {
            let fallback = &candidate.uplink.fallbacks[(wire_index - 1) as usize];
            connect_tcp_fallback_fresh(uplinks, candidate, fallback, target, wire_index).await
        };
        match attempt {
            Ok(connected) => {
                uplinks.record_wire_outcome(
                    candidate.index,
                    TransportKind::Tcp,
                    wire_index,
                    true,
                    total_wires,
                );
                if wire_index != 0 {
                    outline_metrics::record_uplink_selected(
                        "tcp",
                        uplinks.group_name(),
                        &candidate.uplink.name,
                    );
                    debug!(
                        uplink = %candidate.uplink.name,
                        target = %target,
                        wire_index,
                        "TCP fallback wire dial succeeded",
                    );
                }
                return Ok(connected);
            },
            Err(error) => {
                uplinks.record_wire_outcome(
                    candidate.index,
                    TransportKind::Tcp,
                    wire_index,
                    false,
                    total_wires,
                );
                let wire_label = if wire_index == 0 {
                    format!("primary ({})", candidate.uplink.transport)
                } else {
                    let fb = &candidate.uplink.fallbacks[(wire_index - 1) as usize];
                    format!("fallback[{}] ({})", wire_index - 1, fb.transport)
                };
                warn!(
                    uplink = %candidate.uplink.name,
                    target = %target,
                    wire = %wire_label,
                    error = %format!("{error:#}"),
                    "TCP wire dial failed",
                );
                last_err = Some(error.context(format!(
                    "uplink {} {wire_label} failed",
                    candidate.uplink.name,
                )));
            },
        }
    }
    Err(last_err
        .unwrap_or_else(|| anyhow!("uplink {}: no wires available", candidate.uplink.name))
        .context(format!(
            "uplink {}: primary and all {} fallback(s) failed",
            candidate.uplink.name,
            candidate.uplink.fallbacks.len(),
        )))
}

/// Dial a specific wire on `candidate` — primary if `wire_index == 0`,
/// `fallbacks[wire_index - 1]` otherwise. Used by the wire-aware chunk-0
/// failover step to retry a different wire of the same uplink before
/// falling through to a different uplink. Distinct from
/// [`connect_tcp_uplink`] which iterates wires internally and picks the
/// first one to succeed; the chunk-0 failover loop already knows which
/// wire just failed and wants to skip it.
pub(super) async fn connect_tcp_specific_wire(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
    wire_index: u8,
) -> Result<ConnectedTcpUplink> {
    if wire_index == 0 {
        connect_tcp_uplink_primary(uplinks, candidate, target).await
    } else {
        let idx = (wire_index - 1) as usize;
        let fallback = candidate
            .uplink
            .fallbacks
            .get(idx)
            .ok_or_else(|| anyhow!(
                "uplink {} has no fallback at index {}",
                candidate.uplink.name,
                idx,
            ))?;
        connect_tcp_fallback_fresh(uplinks, candidate, fallback, target, wire_index).await
    }
}

async fn connect_tcp_uplink_primary(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<ConnectedTcpUplink> {
    let cache = uplinks.dns_cache();
    if candidate.uplink.transport == UplinkTransport::Shadowsocks {
        let stream = connect_shadowsocks_tcp_with_source(
            cache,
            candidate
                .uplink
                .tcp_addr
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", candidate.uplink.name))?,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            "socks_tcp",
        )
        .await?;
        let setup = WireSetup::from_uplink(&candidate.uplink);
        let (writer, reader) =
            do_tcp_ss_setup_socket(stream, &setup, target, "socks_tcp").await?;
        return Ok(ConnectedTcpUplink {
            writer,
            reader,
            source: TcpUplinkSource::DirectSocket,
            wire_index: 0,
        });
    }

    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        let setup = WireSetup::from_uplink(&candidate.uplink);
        match do_tcp_ss_setup(ws, &setup, target, "socks_tcp", keepalive_interval).await {
            Ok((writer, reader)) => {
                return Ok(ConnectedTcpUplink {
                    writer,
                    reader,
                    source: TcpUplinkSource::Standby,
                    wire_index: 0,
                });
            }
            Err(e) => {
                debug!(
                    uplink = %candidate.uplink.name,
                    error = %format!("{e:#}"),
                    "stale standby TCP pool connection, retrying with fresh dial"
                );
            }
        }
    }

    connect_tcp_uplink_fresh(uplinks, candidate, target).await
}

pub(super) async fn connect_tcp_uplink_fresh(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<ConnectedTcpUplink> {
    #[cfg(feature = "h3")]
    {
        let mode = uplinks.effective_tcp_mode(candidate.index).await;
        if mode == outline_transport::TransportMode::Quic {
            match uplinks
                .connect_tcp_quic_fresh(candidate, target, "socks_tcp")
                .await
            {
                Ok((writer, reader)) => {
                    debug!(
                        uplink = %candidate.uplink.name,
                        target = %target,
                        transport = "quic",
                        "opened raw-QUIC TCP uplink"
                    );
                    return Ok(ConnectedTcpUplink {
                        writer,
                        reader,
                        source: TcpUplinkSource::FreshDial,
                        wire_index: 0,
                    });
                }
                Err(e) => {
                    warn!(
                        uplink = %candidate.uplink.name,
                        target = %target,
                        error = %format!("{e:#}"),
                        fallback = "ws/h2",
                        "raw-QUIC TCP dial failed, falling back to WS over H2"
                    );
                    uplinks.note_advanced_mode_dial_failure(
                        candidate.index,
                        TransportKind::Tcp,
                        &e,
                    );
                    // Fall through to the WS path below; effective_tcp_mode
                    // will now return H2 for the rest of the downgrade window,
                    // and connect_websocket_with_source handles H2 → H1.
                }
            }
        }
    }
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
    let ws = uplinks.connect_tcp_ws_fresh(candidate, "socks_tcp").await?;
    let setup = WireSetup::from_uplink(&candidate.uplink);
    let (writer, reader) =
        do_tcp_ss_setup(ws, &setup, target, "socks_tcp", keepalive_interval).await?;
    Ok(ConnectedTcpUplink {
        writer,
        reader,
        source: TcpUplinkSource::FreshDial,
        wire_index: 0,
    })
}

/// Dial one fallback transport on the parent uplink. Returns a fully-set-up
/// `ConnectedTcpUplink` indistinguishable from the primary path.
///
/// Bypasses the standby pool, mode-downgrade window, RTT-EWMA feed, and
/// cross-transport resume cache — those structures are keyed on the parent's
/// uplink index and primary transport, so a fallback dial must not pollute
/// them. (Active-wire-aware probing and stat tracking are Phase 2.)
///
/// The DNS cache and per-uplink fingerprint scope (which is identity-level,
/// not transport-level) **are** preserved.
pub(super) async fn connect_tcp_fallback_fresh(
    uplinks: &UplinkManager,
    parent: &UplinkCandidate,
    fallback: &FallbackTransport,
    target: &TargetAddr,
    wire_index: u8,
) -> Result<ConnectedTcpUplink> {
    let cache = uplinks.dns_cache();
    let setup = WireSetup::from_fallback(&parent.uplink.name, fallback);
    let source = "socks_tcp_fb";

    if fallback.transport == UplinkTransport::Shadowsocks {
        let addr = fallback
            .tcp_addr
            .as_ref()
            .ok_or_else(|| anyhow!(
                "uplink {} fallback (transport=shadowsocks) missing tcp_addr",
                parent.uplink.name,
            ))?;
        let stream = connect_shadowsocks_tcp_with_source(
            cache,
            addr,
            fallback.fwmark,
            fallback.ipv6_first,
            source,
        )
        .await?;
        let (writer, reader) = do_tcp_ss_setup_socket(stream, &setup, target, source).await?;
        debug!(
            uplink = %parent.uplink.name,
            target = %target,
            transport = "shadowsocks",
            wire = "fallback",
            "opened fallback TCP uplink",
        );
        return Ok(ConnectedTcpUplink {
            writer,
            reader,
            source: TcpUplinkSource::DirectSocket,
            wire_index,
        });
    }

    // WS / VLESS dial — both ride the same WS-family primitives. Mode is
    // taken from the fallback's configured value (no per-fallback downgrade
    // tracking yet — Phase 2 follow-up).
    //
    // Resume-cache participation: keyed on the parent's uplink name (not
    // the wire), so the X-Outline-Resume token issued for a primary dial
    // is presented on the fallback dial too — server-side re-attaches the
    // upstream session, enabling handover-via-resume across wire switches
    // without renegotiating the upstream conversation. SS fallback has no
    // WS layer and no resume mechanism; it always dials fresh.
    let url = fallback
        .tcp_dial_url()
        .ok_or_else(|| anyhow!(
            "uplink {} fallback ({}) missing TCP dial URL",
            parent.uplink.name,
            fallback.transport,
        ))?;
    let mode = fallback.tcp_dial_mode();
    let resume_key = uplinks.resume_cache_key_for(&parent.uplink.name, "tcp");
    let resume_request = global_resume_cache().get(&resume_key);
    let ws = connect_websocket_with_resume(
        cache,
        url,
        mode,
        fallback.fwmark,
        fallback.ipv6_first,
        source,
        resume_request,
    )
    .await
    .with_context(|| format!(
        "fallback dial to {} (uplink {}, transport={}) failed",
        url,
        parent.uplink.name,
        fallback.transport,
    ))?;
    global_resume_cache().store_if_issued(resume_key, ws.issued_session_id());
    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;
    let (writer, reader) = do_tcp_ss_setup(ws, &setup, target, source, keepalive_interval).await?;
    debug!(
        uplink = %parent.uplink.name,
        target = %target,
        transport = %fallback.transport,
        wire = "fallback",
        "opened fallback TCP uplink",
    );
    Ok(ConnectedTcpUplink {
        writer,
        reader,
        source: TcpUplinkSource::FreshDial,
        wire_index,
    })
}

/// Lightweight projection of the wire-credential fields needed by the
/// SS / VLESS setup helpers. Lets the helpers take both an
/// [`UplinkConfig`] (primary path) and a [`FallbackTransport`] (fallback
/// path) by reference without an `&UplinkConfig` synthesis.
///
/// `name` is the **parent uplink's** display name in both cases — the
/// fallback shares identity with its parent for logging / metrics
/// purposes. The wire family / cipher / password / vless_id come from
/// whichever side is actually being dialed.
pub(super) struct WireSetup<'a> {
    pub(super) name: &'a str,
    pub(super) transport: UplinkTransport,
    pub(super) cipher: outline_uplink::CipherKind,
    pub(super) password: &'a str,
    pub(super) vless_id: Option<&'a [u8; 16]>,
}

impl<'a> WireSetup<'a> {
    pub(super) fn from_uplink(uplink: &'a outline_uplink::UplinkConfig) -> Self {
        Self {
            name: &uplink.name,
            transport: uplink.transport,
            cipher: uplink.cipher,
            password: &uplink.password,
            vless_id: uplink.vless_id.as_ref(),
        }
    }

    pub(super) fn from_fallback(
        parent_name: &'a str,
        fallback: &'a outline_uplink::FallbackTransport,
    ) -> Self {
        Self {
            name: parent_name,
            transport: fallback.transport,
            cipher: fallback.cipher,
            password: &fallback.password,
            vless_id: fallback.vless_id.as_ref(),
        }
    }
}

async fn do_tcp_ss_setup(
    ws_stream: outline_transport::TransportStream,
    setup: &WireSetup<'_>,
    target: &TargetAddr,
    source: &'static str,
    keepalive_interval: Option<std::time::Duration>,
) -> Result<(TcpWriter, TcpReader)> {
    let shared_conn_info = ws_stream.shared_connection_info();
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let diag = outline_transport::WsReadDiag {
        conn_id: shared_conn_info.map(|(id, _)| id),
        mode: shared_conn_info.map(|(_, m)| m).unwrap_or("h1"),
        uplink: setup.name.to_string(),
        target: target.to_string(),
    };

    if setup.transport == UplinkTransport::Vless {
        let uuid = setup
            .vless_id
            .ok_or_else(|| anyhow!("uplink {} missing vless_id", setup.name))?;
        let (writer, reader) = outline_transport::vless::vless_tcp_pair_from_ws(
            ws_stream,
            uuid,
            target,
            lifetime,
            diag,
            keepalive_interval,
        );
        debug!(
            uplink = %setup.name,
            target = %target,
            transport = "ws",
            protocol = "vless",
            "opened VLESS uplink"
        );
        return Ok((TcpWriter::Vless(writer), TcpReader::Vless(reader)));
    }

    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = setup.cipher.derive_master_key(setup.password)?;
    let (writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, setup.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let reader = TcpShadowsocksReader::new(ws_stream, setup.cipher, &master_key, lifetime, ctrl_tx);
    let mut writer = TcpWriter::Ws(writer);
    let reader = TcpReader::Ws(reader)
        .with_request_salt(writer.request_salt())
        .with_diag(diag);
    send_initial_ss_target(&mut writer, setup, target, "ws").await?;
    Ok((writer, reader))
}

async fn do_tcp_ss_setup_socket(
    stream: tokio::net::TcpStream,
    setup: &WireSetup<'_>,
    target: &TargetAddr,
    source: &'static str,
) -> Result<(TcpWriter, TcpReader)> {
    let (reader_half, writer_half) = stream.into_split();
    let master_key = setup.cipher.derive_master_key(setup.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        setup.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let reader = TcpShadowsocksReader::new_socket(reader_half, setup.cipher, &master_key, lifetime);
    let mut writer = TcpWriter::Socket(writer);
    let reader = TcpReader::Socket(reader).with_request_salt(writer.request_salt());
    send_initial_ss_target(&mut writer, setup, target, "socket").await?;
    Ok((writer, reader))
}

async fn send_initial_ss_target(
    writer: &mut TcpWriter,
    setup: &WireSetup<'_>,
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
