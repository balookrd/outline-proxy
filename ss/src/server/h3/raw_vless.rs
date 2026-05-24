use std::sync::Arc;

use anyhow::{Result, anyhow};
use tracing::{debug, warn};

use super::super::transport::{
    OversizeStream, StreamKind, VlessQuicConn, classify_accept_bi,
    handle_raw_vless_quic_stream_with_prefix, is_handshake_rejected, is_normal_h3_shutdown,
    serve_raw_vless_oversize_records, serve_raw_vless_quic_datagrams,
};
use super::H3ConnectionCtx;

pub(super) async fn handle_raw_vless_connection(
    connection: quinn::Connection,
    ctx: Arc<H3ConnectionCtx>,
) -> Result<()> {
    debug!(remote = %connection.remote_address(), "raw VLESS QUIC connection accepted");
    let mtu_aware = connection
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .is_some_and(|bytes| bytes == b"vless-mtu");
    let connection = Arc::new(connection);
    let conn_state = Arc::new(VlessQuicConn::new());

    let dgram_conn = Arc::clone(&connection);
    let dgram_state = Arc::clone(&conn_state);
    let dgram_server = Arc::clone(&ctx.vless_server);
    let dgram_task = tokio::spawn(async move {
        serve_raw_vless_quic_datagrams(dgram_conn, dgram_state, dgram_server).await
    });

    let bidi_result = loop {
        let (send, mut recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed)
            | Err(quinn::ConnectionError::TimedOut)
            | Err(quinn::ConnectionError::Reset) => break Ok(()),
            Err(error) => break Err(anyhow!(error).context("vless raw-quic accept_bi failed")),
        };
        let stream_permit = match ctx.stream_semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break Ok(()),
        };

        // On the MTU-aware ALPN, peek 8 bytes off every accepted bidi
        // stream to disambiguate the connection-level oversize-record
        // stream (magic prefix, opened at most once per connection)
        // from a plain VLESS request stream (header byte 0 is
        // VLESS_VERSION = 0x00, never matches the magic). On the legacy
        // ALPN we skip the peek and treat every stream as a request.
        let prefix_or_kind = if mtu_aware {
            match classify_accept_bi(&mut recv).await {
                Ok(kind) => kind,
                Err(error) => {
                    warn!(?error, "vless raw-quic accept_bi peek failed");
                    drop(stream_permit);
                    continue;
                },
            }
        } else {
            StreamKind::Other { consumed: [0u8; 8] }
        };

        match prefix_or_kind {
            StreamKind::Oversize => {
                let stream = Arc::new(OversizeStream::from_accept_validated(send, recv));
                let installed = conn_state.oversize_slot.install(stream);
                let state_for_pump = Arc::clone(&conn_state);
                tokio::spawn(async move {
                    let _permit = stream_permit;
                    if let Err(error) =
                        serve_raw_vless_oversize_records(installed, state_for_pump).await
                    {
                        debug!(?error, "vless raw-quic oversize-record pump terminated");
                    }
                });
            },
            StreamKind::Other { consumed } => {
                let prefix = if mtu_aware { consumed.to_vec() } else { Vec::new() };
                let server = Arc::clone(&ctx.vless_server);
                let route = Arc::clone(&ctx.raw_vless_route);
                let conn_for_stream = Arc::clone(&connection);
                let state_for_stream = Arc::clone(&conn_state);
                tokio::spawn(async move {
                    let _permit = stream_permit;
                    if let Err(error) = handle_raw_vless_quic_stream_with_prefix(
                        send,
                        recv,
                        prefix,
                        server,
                        route,
                        conn_for_stream,
                        state_for_stream,
                    )
                    .await
                        && !is_normal_h3_shutdown(&error)
                    {
                        if is_handshake_rejected(&error) {
                            debug!(?error, "vless raw-quic handshake rejected (probe-sinked)");
                        } else {
                            warn!(?error, "vless raw-quic stream terminated with error");
                        }
                    }
                });
            },
        }
    };
    dgram_task.abort();
    let _ = dgram_task.await;
    bidi_result
}
