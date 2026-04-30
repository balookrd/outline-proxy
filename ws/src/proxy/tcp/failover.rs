use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tracing::{debug, warn};

use outline_transport::{
    TcpReader, TcpWriter,
    TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source,
};
use socks5_proto::TargetAddr;
use outline_uplink::{TransportKind, UplinkCandidate, UplinkManager, UplinkTransport};

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
}

/// All mutable state that tracks the currently-active uplink during the
/// phase-1 failover loop.  Consolidates what were previously five separate
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
    }

    /// Replace only the transport (writer/reader/source) while keeping the
    /// same uplink identity.  Used when a warm-standby socket proves stale
    /// and we retry the same uplink with a fresh dial.
    pub(super) fn replace_transport(&mut self, reconnected: ConnectedTcpUplink) {
        self.writer = reconnected.writer;
        self.reader = reconnected.reader;
        self.source = reconnected.source;
    }
}

pub(super) async fn connect_tcp_uplink(
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
        let (writer, reader) =
            do_tcp_ss_setup_socket(stream, &candidate.uplink, target, "socks_tcp").await?;
        return Ok(ConnectedTcpUplink {
            writer,
            reader,
            source: TcpUplinkSource::DirectSocket,
        });
    }

    let keepalive_interval = uplinks.load_balancing().tcp_ws_keepalive_interval;

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        match do_tcp_ss_setup(ws, &candidate.uplink, target, "socks_tcp", keepalive_interval).await {
            Ok((writer, reader)) => {
                return Ok(ConnectedTcpUplink {
                    writer,
                    reader,
                    source: TcpUplinkSource::Standby,
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
    let (writer, reader) =
        do_tcp_ss_setup(ws, &candidate.uplink, target, "socks_tcp", keepalive_interval).await?;
    Ok(ConnectedTcpUplink {
        writer,
        reader,
        source: TcpUplinkSource::FreshDial,
    })
}

async fn do_tcp_ss_setup(
    ws_stream: outline_transport::TransportStream,
    uplink: &outline_uplink::UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
    keepalive_interval: Option<std::time::Duration>,
) -> Result<(TcpWriter, TcpReader)> {
    let shared_conn_info = ws_stream.shared_connection_info();
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let diag = outline_transport::WsReadDiag {
        conn_id: shared_conn_info.map(|(id, _)| id),
        mode: shared_conn_info.map(|(_, m)| m).unwrap_or("h1"),
        uplink: uplink.name.clone(),
        target: target.to_string(),
    };

    if uplink.transport == UplinkTransport::Vless {
        let uuid = uplink
            .vless_id
            .as_ref()
            .ok_or_else(|| anyhow!("uplink {} missing vless_id", uplink.name))?;
        let (writer, reader) = outline_transport::vless::vless_tcp_pair_from_ws(
            ws_stream,
            uuid,
            target,
            lifetime,
            diag,
            keepalive_interval,
        );
        debug!(
            uplink = %uplink.name,
            target = %target,
            transport = "ws",
            protocol = "vless",
            "opened VLESS uplink"
        );
        return Ok((TcpWriter::Vless(writer), TcpReader::Vless(reader)));
    }

    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let (writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let reader = TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key, lifetime, ctrl_tx);
    let mut writer = TcpWriter::Ws(writer);
    let reader = TcpReader::Ws(reader)
        .with_request_salt(writer.request_salt())
        .with_diag(diag);
    send_initial_ss_target(&mut writer, uplink, target, "ws").await?;
    Ok((writer, reader))
}

async fn do_tcp_ss_setup_socket(
    stream: tokio::net::TcpStream,
    uplink: &outline_uplink::UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
) -> Result<(TcpWriter, TcpReader)> {
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let reader = TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime);
    let mut writer = TcpWriter::Socket(writer);
    let reader = TcpReader::Socket(reader).with_request_salt(writer.request_salt());
    send_initial_ss_target(&mut writer, uplink, target, "socket").await?;
    Ok((writer, reader))
}

async fn send_initial_ss_target(
    writer: &mut TcpWriter,
    uplink: &outline_uplink::UplinkConfig,
    target: &TargetAddr,
    transport: &'static str,
) -> Result<()> {
    let target_wire = target.to_wire_bytes()?;
    writer
        .send_chunk(&target_wire)
        .await
        .context("failed to send target address")?;
    debug!(
        uplink = %uplink.name,
        target = %target,
        target_wire_len = target_wire.len(),
        transport = transport,
        ss2022 = uplink.cipher.is_ss2022(),
        "sent initial Shadowsocks target header to uplink"
    );
    Ok(())
}
