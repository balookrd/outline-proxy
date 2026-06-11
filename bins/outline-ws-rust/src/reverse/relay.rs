//! Per-session relay over a reverse peer's QUIC carrier.
//!
//! Opens one SS-TCP bidi stream on the accepted carrier (the peer's `ss`
//! server `accept_bi`-loops it), writes the SS2022 target header, replies to
//! the SOCKS5 client, then splices bytes both ways. The wire framing is the
//! exact forward SS-over-QUIC pipeline (`ss_tcp_over_connection` +
//! `to_wire_bytes` target header); only the carrier was accepted instead of
//! dialed. A deliberately simple bidirectional splice — no chunk-0 failover
//! / mid-session retry (those are uplink-manager concepts with no meaning
//! for a single pinned reverse carrier).

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use outline_metrics as metrics;
use outline_transport::{
    QuicTcpReader, QuicTcpWriter, UpstreamTransportGuard, ss_tcp_over_connection,
};
use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use socks5_proto::{SOCKS_REP_SUCCESS, TargetAddr, send_reply, socket_addr_to_target};

use super::peer_registry::ReversePeer;

/// Relay one SOCKS5 CONNECT through `peer`. Errors before the SOCKS reply
/// surface to the caller (which closes the client); after the reply the
/// splice runs to completion.
pub(crate) async fn serve_reverse_tcp(
    client: TcpStream,
    peer: Arc<ReversePeer>,
    target: TargetAddr,
) -> Result<()> {
    let session = metrics::track_session("tcp");
    let result = relay_inner(client, &peer, &target).await;
    session.finish(result.is_ok());
    result
}

async fn relay_inner(
    mut client: TcpStream,
    peer: &Arc<ReversePeer>,
    target: &TargetAddr,
) -> Result<()> {
    let lifetime = UpstreamTransportGuard::new("reverse_tcp", "tcp");
    let (mut writer, reader) =
        ss_tcp_over_connection(&peer.conn, peer.cipher, &peer.master_key, lifetime)
            .await
            .context("reverse: failed to open SS-TCP stream on peer carrier")?;

    // Bind the response reader to the request salt and send the SS2022
    // target header as the first chunk — identical to the forward dial.
    let request_salt = writer.request_salt();
    let reader = reader.with_request_salt(request_salt);
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("reverse: failed to send target header")?;

    let bound = socket_addr_to_target(client.local_addr()?);
    send_reply(&mut client, SOCKS_REP_SUCCESS, &bound).await?;

    let (client_read, client_write) = client.into_split();
    splice(client_read, client_write, writer, reader, Arc::clone(&peer.label)).await
}

/// Bidirectional splice with TCP half-close semantics: client EOF triggers
/// an upstream half-close (the downlink keeps draining in-flight bytes);
/// upstream EOF shuts the client write half down. Both directions are
/// awaited so neither truncates the other.
async fn splice(
    mut client_read: OwnedReadHalf,
    mut client_write: OwnedWriteHalf,
    mut writer: QuicTcpWriter,
    mut reader: QuicTcpReader,
    label: Arc<str>,
) -> Result<()> {
    let uplink = async move {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        loop {
            let read = client_read
                .read(&mut buf)
                .await
                .context("reverse: client read failed")?;
            if read == 0 {
                writer.close().await.context("reverse: upstream half-close failed")?;
                break;
            }
            writer
                .send_chunk(&buf[..read])
                .await
                .context("reverse: upstream send failed")?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let downlink = async move {
        loop {
            let chunk = match reader.read_chunk().await {
                Ok(chunk) => chunk,
                Err(_) if reader.closed_cleanly => break,
                Err(error) => return Err(error).context("reverse: upstream read failed"),
            };
            if chunk.is_empty() {
                break;
            }
            client_write
                .write_all(&chunk)
                .await
                .context("reverse: client write failed")?;
        }
        client_write
            .shutdown()
            .await
            .context("reverse: client shutdown failed")?;
        Ok::<(), anyhow::Error>(())
    };

    let (up, down) = tokio::join!(uplink, downlink);
    // Surface the first error but let both directions finish first so a
    // clean half-close on one side is not reported as a failure.
    if let Err(error) = up {
        tracing::debug!(peer = %label, ?error, "reverse uplink direction ended with error");
        return Err(error);
    }
    down
}
