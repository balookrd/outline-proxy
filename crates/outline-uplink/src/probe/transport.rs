//! Shared TCP transport setup for probes that need a real Shadowsocks stream
//! (HTTP probe, TCP-tunnel probe).
//!
//! Both probe kinds dial the uplink the same way — tunnelling through
//! WebSocket — wrap the resulting byte stream in Shadowsocks AEAD
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
    DialNetworkOptions, DnsCache, TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, TcpWriter,
    TransportDialOptions, TransportOperation, UpstreamTransportGuard, connect_transport,
};

use crate::config::{SsPathKind, TargetAddr, TransportMode, UplinkConfig, UplinkTransport};

/// Connects a probe's Shadowsocks TCP stream (tunnelled through WebSocket) and
/// returns the framed writer/reader halves plus a downgrade marker.  `source`
/// is the connect-source tag that propagates into transport metrics and trace
/// spans; `probe_label` is used only to build human-readable error contexts.
///
/// The third tuple element is `Some(requested_mode)` iff the underlying
/// `connect_transport` returned a stream at a lower mode than
/// asked for (host-level `ws_mode_cache` clamp or inline H3→H2/H1 fallback).
/// The probe orchestrator surfaces this through `ProbeOutcome` so the
/// uplink-manager can mirror the downgrade into its per-uplink window even
/// though the probe itself succeeded.
pub(super) async fn connect_probe_tcp(
    cache: &DnsCache,
    uplink: &UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
    probe_label: &str,
    effective_tcp_mode: TransportMode,
    dial_limit: Arc<Semaphore>,
) -> Result<(TcpWriter, TcpReader, Option<TransportMode>)> {
    // Scope the per-uplink padding override over the whole probe dial + build:
    // the probe transport reads `effective_carrier_padding` when it splits and
    // builds the reader/writer (after `dial_in_uplink_scope` hands back the
    // stream), so the build must run inside the override too — otherwise a
    // probe to a padded per-uplink path would dial plain, get rejected, and
    // flap the uplink unhealthy. raw-QUIC is never padded, so the QUIC arm
    // inside is a no-op under the scope.
    crate::dial::with_uplink_padding_scope(
        uplink,
        connect_probe_tcp_inner(
            cache,
            uplink,
            target,
            source,
            probe_label,
            effective_tcp_mode,
            dial_limit,
        ),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_probe_tcp_inner(
    cache: &DnsCache,
    uplink: &UplinkConfig,
    target: &TargetAddr,
    source: &'static str,
    probe_label: &str,
    effective_tcp_mode: TransportMode,
    dial_limit: Arc<Semaphore>,
) -> Result<(TcpWriter, TcpReader, Option<TransportMode>)> {
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new(source, "tcp");
    let _permit = dial_limit.acquire_owned().await.expect("probe dial semaphore closed");

    #[cfg(feature = "quic")]
    if effective_tcp_mode == TransportMode::Quic
        && (uplink.transport == UplinkTransport::Ss || uplink.transport == UplinkTransport::Vless)
    {
        let url = uplink
            .tcp_dial_url()
            .ok_or_else(|| anyhow!("uplink {} missing dial URL", uplink.name))?;
        return match uplink.transport {
            UplinkTransport::Vless => {
                let uuid = uplink
                    .vless_id
                    .as_ref()
                    .ok_or_else(|| anyhow!("uplink {} missing vless_id", uplink.name))?;
                let (w, r) = crate::dial::dial_in_uplink_scope(
                    uplink,
                    outline_transport::connect_vless_tcp_quic(
                        cache,
                        url,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        source,
                        uuid,
                        target,
                        lifetime,
                    ),
                )
                .await
                .with_context(|| TransportOperation::Connect {
                    target: format!("{probe_label} vless quic for uplink {}", uplink.name),
                })?;
                // Raw QUIC bypasses the WS layer, so there is no
                // `ws_mode_cache` clamp to surface here.
                Ok((TcpWriter::Vless(w), TcpReader::Vless(r), None))
            },
            UplinkTransport::Ss => {
                let (w, r) = crate::dial::dial_in_uplink_scope(
                    uplink,
                    outline_transport::connect_ss_tcp_quic(
                        cache,
                        url,
                        uplink.fwmark,
                        uplink.ipv6_first,
                        source,
                        uplink.cipher,
                        &master_key,
                        Arc::clone(&lifetime),
                    ),
                )
                .await
                .with_context(|| TransportOperation::Connect {
                    target: format!("{probe_label} ss quic for uplink {}", uplink.name),
                })?;
                let request_salt = w.request_salt();
                let r = r.with_request_salt(request_salt);
                Ok((TcpWriter::QuicSs(w), TcpReader::QuicSs(r), None))
            },
        };
    }

    match uplink.transport {
        UplinkTransport::Ss => {
            let ws_stream = crate::dial::dial_in_uplink_scope(
                uplink,
                connect_transport(
                    TransportDialOptions::new(
                        cache,
                        uplink.tcp_dial_url().ok_or_else(|| {
                            anyhow!("uplink {} missing tcp dial URL", uplink.name)
                        })?,
                        effective_tcp_mode,
                        source,
                    )
                    .with_network(DialNetworkOptions {
                        fwmark: uplink.fwmark,
                        ipv6_first: uplink.ipv6_first,
                    })
                    .with_combined_ss_kind(uplink.combined_ss_kind(SsPathKind::Tcp)),
                ),
            )
            .await
            .with_context(|| TransportOperation::Connect {
                target: format!("{probe_label} websocket for uplink {}", uplink.name),
            })?;
            let downgraded_from = ws_stream.downgraded_from();
            let shared_conn_info = ws_stream.shared_connection_info();
            // Capture the authoritative H3 flag before `split()` consumes the
            // stream; the read-idle watchdog gates on `diag.is_h3`.
            let is_h3 = ws_stream.is_h3();
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
                is_h3,
                uplink: uplink.name.clone(),
                target: target.to_string(),
            };
            let reader =
                TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key, lifetime, ctrl_tx)
                    .with_request_salt(request_salt)
                    .with_diag(diag);
            Ok((TcpWriter::Ws(writer), TcpReader::Ws(reader), downgraded_from))
        },
        UplinkTransport::Vless => {
            let ws_stream = crate::dial::dial_in_uplink_scope(
                uplink,
                connect_transport(
                    TransportDialOptions::new(
                        cache,
                        uplink.tcp_dial_url().ok_or_else(|| {
                            anyhow!("uplink {} missing vless dial URL", uplink.name)
                        })?,
                        effective_tcp_mode,
                        source,
                    )
                    .with_network(DialNetworkOptions {
                        fwmark: uplink.fwmark,
                        ipv6_first: uplink.ipv6_first,
                    }),
                ),
            )
            .await
            .with_context(|| TransportOperation::Connect {
                target: format!("{probe_label} vless transport for uplink {}", uplink.name),
            })?;
            let downgraded_from = ws_stream.downgraded_from();
            let shared_conn_info = ws_stream.shared_connection_info();
            let uuid = uplink
                .vless_id
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} missing vless_id", uplink.name))?;
            let diag = outline_transport::WsReadDiag {
                conn_id: shared_conn_info.map(|(id, _)| id),
                mode: shared_conn_info.map(|(_, m)| m).unwrap_or("h1"),
                is_h3: ws_stream.is_h3(),
                uplink: uplink.name.clone(),
                target: target.to_string(),
            };
            let (writer, reader) = outline_transport::vless::vless_tcp_pair_from_ws(
                ws_stream, uuid, target, lifetime, diag, None,
            );
            Ok((TcpWriter::Vless(writer), TcpReader::Vless(reader), downgraded_from))
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
