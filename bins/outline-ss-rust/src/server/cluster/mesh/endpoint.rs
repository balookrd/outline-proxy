//! Mesh QUIC endpoint: one socket that both listens for inbound relays (a home
//! receiving from an edge) and dials peers (an edge relaying to a home). Both
//! directions authenticate with the same PSK-derived mutual pin.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use quinn::{Connection, ConnectionError, Endpoint, RecvStream, SendStream};

use super::frame::OpenHeader;
use super::tls::{
    MESH_SERVER_NAME, MeshIdentity, build_mesh_client_quic_config, build_mesh_server_quic_config,
};

/// Upper bound on the length-prefixed OPEN header a peer may send, so a
/// malformed prefix can't drive an unbounded read/allocation.
const MAX_OPEN_HEADER_LEN: usize = 4096;

/// One relayed session's bidirectional QUIC stream.
pub(in crate::server) struct MeshStream {
    pub(in crate::server) send: SendStream,
    pub(in crate::server) recv: RecvStream,
}

/// A bound mesh endpoint, usable both as listener and dialer. Cloneable (the
/// inner quinn endpoint is an `Arc`), so the listener accept-loop and the peer
/// pool can share one socket.
#[derive(Clone)]
pub(in crate::server) struct MeshEndpoint {
    endpoint: Endpoint,
}

impl MeshEndpoint {
    /// Binds the mesh socket on `listen`, installing this node's PSK-derived
    /// server config (for inbound) and default client config (for dialing).
    pub(in crate::server) fn bind(listen: SocketAddr, identity: &MeshIdentity) -> Result<Self> {
        let server_config = build_mesh_server_quic_config(identity)?;
        let client_config = build_mesh_client_quic_config(identity)?;
        let mut endpoint = Endpoint::server(server_config, listen)
            .with_context(|| format!("binding mesh endpoint on {listen}"))?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    /// The actual bound local address (useful when binding to port 0).
    pub(in crate::server) fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().context("mesh endpoint local_addr")
    }

    /// Dials a peer, completing the mutual-pin handshake. Fails if the peer
    /// does not present a certificate matching our PSK-derived pin.
    pub(in crate::server) async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        let conn = self
            .endpoint
            .connect(addr, MESH_SERVER_NAME)
            .with_context(|| format!("initiating mesh dial to {addr}"))?
            .await
            .with_context(|| format!("mesh handshake with {addr}"))?;
        Ok(conn)
    }

    /// Accepts the next inbound peer connection, or `None` once the endpoint is
    /// closed.
    pub(in crate::server) async fn accept(&self) -> Option<Result<Connection>> {
        let incoming = self.endpoint.accept().await?;
        Some(incoming.await.context("accepting mesh connection"))
    }

    /// Closes the endpoint and waits for it to become idle.
    pub(in crate::server) async fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"mesh shutdown");
        self.endpoint.wait_idle().await;
    }
}

/// Opens a relay stream to `conn`, writing the length-prefixed OPEN header the
/// home reads back with [`accept_relay`].
pub(in crate::server) async fn open_relay_stream(
    conn: &Connection,
    header: &OpenHeader,
) -> Result<MeshStream> {
    let (mut send, recv) = conn.open_bi().await.context("opening mesh relay stream")?;
    let open = header.encode();
    send.write_all(&(open.len() as u32).to_be_bytes())
        .await
        .context("writing mesh OPEN length")?;
    send.write_all(&open).await.context("writing mesh OPEN header")?;
    Ok(MeshStream { send, recv })
}

/// Why [`accept_relay`] yielded no relay stream. The home's accept loop must
/// tell the two apart: a failure that killed the whole connection ends it, but a
/// failure confined to one stream must not — the connection is still carrying
/// live relays (and the control-datagram receiver) that depend on the loop.
#[derive(Debug)]
pub(in crate::server) enum AcceptRelayError {
    /// The QUIC connection is gone: the peer closed it, it timed out, or the
    /// transport failed. No further stream will ever arrive on it.
    Connection(ConnectionError),
    /// One stream failed before it could be served — reset by the peer between
    /// `open_bi` and the OPEN header, or carrying a header this build cannot
    /// parse (a peer on a newer wire version during a rolling upgrade). The
    /// connection itself is unaffected. A connection that dies mid-header also
    /// lands here; the next `accept_relay` then reports it as `Connection`.
    Stream(anyhow::Error),
}

/// Accepts the next relay stream on `conn`, reading and parsing its OPEN
/// header. The remaining stream bytes are the relayed carrier payload.
pub(in crate::server) async fn accept_relay(
    conn: &Connection,
) -> std::result::Result<(OpenHeader, MeshStream), AcceptRelayError> {
    let (send, mut recv) = conn.accept_bi().await.map_err(AcceptRelayError::Connection)?;
    let header = read_open_header(&mut recv).await.map_err(AcceptRelayError::Stream)?;
    Ok((header, MeshStream { send, recv }))
}

/// Reads the length-prefixed OPEN header prefixing a relay stream.
async fn read_open_header(recv: &mut RecvStream) -> Result<OpenHeader> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("reading mesh OPEN length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_OPEN_HEADER_LEN {
        bail!("mesh OPEN header too long: {len}");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.context("reading mesh OPEN header")?;
    OpenHeader::parse(&buf)
}

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;
