//! Per-session TCP relay over a reverse peer's QUIC carrier.
//!
//! Opens one bidi stream on the accepted carrier (the peer's `ss` server
//! `accept_bi`-loops it), frames it per the peer's protocol — SS2022 target
//! header for an SS peer, a VLESS request header for a VLESS peer — replies to
//! the SOCKS5 client, then splices bytes both ways. The wire framing is the
//! exact forward pipeline (`ss_tcp_over_connection` / `vless_tcp_over_connection`);
//! only the carrier was accepted instead of dialed. A deliberately simple
//! bidirectional splice — no chunk-0 failover / mid-session retry (those are
//! uplink-manager concepts with no meaning for a single pinned reverse carrier).

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use outline_metrics as metrics;
use outline_transport::{
    QuicTcpReader, QuicTcpWriter, UpstreamTransportGuard, VlessTcpReader, VlessTcpWriter,
    ss_tcp_over_connection, vless_tcp_over_connection,
};
use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use socks5_proto::{SOCKS_REP_SUCCESS, TargetAddr, send_reply, socket_addr_to_target};

use super::peer_registry::{ReversePeer, ReversePeerCreds};

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
    let bound = socket_addr_to_target(client.local_addr()?);
    let label = Arc::clone(&peer.label);

    match &peer.creds {
        ReversePeerCreds::Ss { cipher, master_key, .. } => {
            let (mut writer, reader) =
                ss_tcp_over_connection(&peer.conn, *cipher, master_key, lifetime)
                    .await
                    .context("reverse: failed to open SS-TCP stream on peer carrier")?;
            // Bind the response reader to the request salt and send the SS2022
            // target header as the first chunk — identical to the forward dial.
            let request_salt = writer.request_salt();
            let reader = reader.with_request_salt(request_salt);
            writer
                .send_chunk(&target.to_wire_bytes()?)
                .await
                .context("reverse: failed to send SS target header")?;
            send_reply(&mut client, SOCKS_REP_SUCCESS, &bound).await?;
            let (client_read, client_write) = client.into_split();
            splice(client_read, client_write, writer, reader, label).await
        },
        ReversePeerCreds::Vless { uuid } => {
            let (mut writer, reader) =
                vless_tcp_over_connection(&peer.conn, uuid, target, lifetime)
                    .await
                    .context("reverse: failed to open VLESS-TCP stream on peer carrier")?;
            // Flush the VLESS request header eagerly (empty payload) so a
            // server-first upstream sees the connection before the client
            // sends anything — the header carries the target.
            writer
                .send_chunk(&[])
                .await
                .context("reverse: failed to send VLESS request header")?;
            send_reply(&mut client, SOCKS_REP_SUCCESS, &bound).await?;
            let (client_read, client_write) = client.into_split();
            splice(client_read, client_write, writer, reader, label).await
        },
    }
}

/// Minimal chunk-writer/reader surface the splice needs, so it works over
/// either the SS (`QuicTcp*`) or VLESS (`VlessTcp*`) framing without an enum.
trait ReverseUpstreamWriter {
    async fn send_chunk(&mut self, payload: &[u8]) -> Result<()>;
    async fn close(&mut self) -> Result<()>;
}

trait ReverseUpstreamReader {
    async fn read_chunk(&mut self) -> Result<Vec<u8>>;
    fn closed_cleanly(&self) -> bool;
}

impl ReverseUpstreamWriter for QuicTcpWriter {
    async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        QuicTcpWriter::send_chunk(self, payload).await
    }
    async fn close(&mut self) -> Result<()> {
        QuicTcpWriter::close(self).await
    }
}

impl ReverseUpstreamWriter for VlessTcpWriter {
    async fn send_chunk(&mut self, payload: &[u8]) -> Result<()> {
        VlessTcpWriter::send_chunk(self, payload).await
    }
    async fn close(&mut self) -> Result<()> {
        VlessTcpWriter::close(self).await
    }
}

impl ReverseUpstreamReader for QuicTcpReader {
    async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        QuicTcpReader::read_chunk(self).await
    }
    fn closed_cleanly(&self) -> bool {
        self.closed_cleanly
    }
}

impl ReverseUpstreamReader for VlessTcpReader {
    async fn read_chunk(&mut self) -> Result<Vec<u8>> {
        VlessTcpReader::read_chunk(self).await
    }
    fn closed_cleanly(&self) -> bool {
        VlessTcpReader::closed_cleanly(self)
    }
}

/// Bidirectional splice with TCP half-close semantics: client EOF triggers
/// an upstream half-close (the downlink keeps draining in-flight bytes);
/// upstream EOF shuts the client write half down. Both directions are
/// awaited so neither truncates the other.
async fn splice<W: ReverseUpstreamWriter, R: ReverseUpstreamReader>(
    mut client_read: OwnedReadHalf,
    mut client_write: OwnedWriteHalf,
    mut writer: W,
    mut reader: R,
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
                Err(_) if reader.closed_cleanly() => break,
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
