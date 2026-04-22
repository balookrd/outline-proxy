//! Shared TCP transport setup for probes that need a real Shadowsocks stream
//! (HTTP probe, TCP-tunnel probe).
//!
//! Both probe kinds dial the uplink the same way — optionally tunnelling
//! through WebSocket — wrap the resulting byte stream in Shadowsocks AEAD
//! reader/writer halves, and return them to the caller for the probe-specific
//! request/response exchange.  Keeping this in one place lets the two
//! probe modules focus on their protocol instead of repeating ~60 lines of
//! transport plumbing each.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use tokio::sync::Semaphore;
use tracing::debug;

use outline_transport::{
    DnsCache, TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, TcpWriter,
    TransportOperation, UpstreamTransportGuard, connect_shadowsocks_tcp_with_source,
    connect_websocket_with_source,
};

use crate::config::{TargetAddr, UplinkConfig, UplinkTransport, WsTransportMode};

/// Connects a probe's Shadowsocks TCP stream (WebSocket or direct socket) and
/// returns the framed writer/reader halves.  `source` is the connect-source
/// tag that propagates into transport metrics and trace spans; `probe_label`
/// is used only to build human-readable error contexts.
pub(super) async fn connect_probe_tcp(
    cache: &DnsCache,
    uplink: &UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
    probe_label: &str,
    effective_tcp_mode: WsTransportMode,
    dial_limit: Arc<Semaphore>,
) -> Result<(TcpWriter, TcpReader)> {
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let _permit = dial_limit
        .acquire_owned()
        .await
        .expect("probe dial semaphore closed");

    match uplink.transport {
        UplinkTransport::Ws => {
            let ws_stream = connect_websocket_with_source(
                cache,
                uplink
                    .tcp_ws_url
                    .as_ref()
                    .ok_or_else(|| anyhow!("uplink {} missing tcp_ws_url", uplink.name))?,
                effective_tcp_mode,
                uplink.fwmark,
                uplink.ipv6_first,
                source,
            )
            .await
            .with_context(|| TransportOperation::Connect {
                target: format!("{probe_label} websocket for uplink {}", uplink.name),
            })?;
            let shared_conn_info = ws_stream.shared_connection_info();
            let (ws_sink, ws_stream) = ws_stream.split();
            let (writer, ctrl_tx) = TcpShadowsocksWriter::connect(
                ws_sink,
                uplink.cipher,
                &master_key,
                Arc::clone(&lifetime),
            )
            .await?;
            let request_salt = writer.request_salt();
            let diag = outline_transport::WsReadDiag {
                conn_id: shared_conn_info.map(|(id, _)| id),
                mode: shared_conn_info.map(|(_, m)| m).unwrap_or("h1"),
                uplink: uplink.name.clone(),
                target: target.to_string(),
            };
            let reader = TcpShadowsocksReader::new(
                ws_stream,
                uplink.cipher,
                &master_key,
                lifetime,
                ctrl_tx,
            )
            .with_request_salt(request_salt)
            .with_diag(diag);
            Ok((TcpWriter::Ws(writer), TcpReader::Ws(reader)))
        },
        UplinkTransport::Shadowsocks => {
            let stream = connect_shadowsocks_tcp_with_source(
                cache,
                uplink
                    .tcp_addr
                    .as_ref()
                    .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", uplink.name))?,
                uplink.fwmark,
                uplink.ipv6_first,
                source,
            )
            .await
            .with_context(|| TransportOperation::Connect {
                target: format!("{probe_label} shadowsocks socket for uplink {}", uplink.name),
            })?;
            let (reader_half, writer_half) = stream.into_split();
            let writer = TcpShadowsocksWriter::connect_socket(
                writer_half,
                uplink.cipher,
                &master_key,
                Arc::clone(&lifetime),
            )?;
            let request_salt = writer.request_salt();
            let reader = TcpShadowsocksReader::new_socket(
                reader_half,
                uplink.cipher,
                &master_key,
                lifetime,
            )
            .with_request_salt(request_salt);
            Ok((TcpWriter::Socket(writer), TcpReader::Socket(reader)))
        },
    }
}

/// Best-effort teardown for a Shadowsocks TCP probe writer.  Close failures
/// are logged at debug level rather than surfaced to the caller — by the time
/// we get here the probe result has already been decided and the interesting
/// error is whatever led us to tear down in the first place.
pub(super) async fn close_probe_tcp_writer(
    uplink_name: &str,
    probe: &'static str,
    writer: &mut TcpWriter,
) {
    if let Err(error) = writer.close().await {
        debug!(
            uplink = %uplink_name,
            transport = "tcp",
            probe,
            error = %format!("{error:#}"),
            "probe transport close returned error during teardown"
        );
    }
}

