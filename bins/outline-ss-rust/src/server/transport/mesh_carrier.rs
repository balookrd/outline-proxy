//! `WsSocket` adapter over a mesh relay stream.
//!
//! On the home side of a relayed session the carrier is not a WebSocket but a
//! QUIC bidirectional stream (`MeshStream`) carrying the still-encrypted
//! application bytes an edge forwarded. To reuse the existing accept path
//! (`run_tcp_relay` / the VLESS relay, which own crypto, upstream and
//! park/unpark) unchanged, we wrap the mesh stream in a [`WsSocket`] whose
//! "frames" are just byte chunks: `recv` reads a chunk and reports it as a
//! `Binary` frame, `send` writes a binary frame's bytes straight to the
//! stream. The downstream padding decoder and AEAD are byte-stream oriented, so
//! chunk boundaries do not matter.
//!
//! Keepalive/close semantics mirror the H3 carrier: `is_h3()` is `true` so the
//! relay never emits a server→client `Ping` and never runs pong-deadline
//! reaping — QUIC's own keep-alive/idle-timeout detects a dead peer. Control
//! frames other than close are no-ops on the wire; close finishes the stream.

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use outline_wire::padding::PaddingScheme;
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc;

use super::throughput_monitor::ThroughputMonitor;
use super::ws_socket::{WsFrame, WsSocket};
use crate::metrics::{AppProtocol, Protocol};
use crate::server::cluster::mesh::MeshStream;
use crate::server::nat::UdpResponseSender;

/// Max bytes pulled from the stream per `recv`. A coarse read granularity; the
/// downstream decoder reassembles across chunks regardless.
const MESH_READ_CHUNK: usize = 256 * 1024;

/// A "frame" over the mesh byte stream. Only `Binary` carries payload; the
/// control variants exist to satisfy the relay's `WsSocket` usage and map to
/// stream finish / no-op.
pub(in crate::server) enum MeshMsg {
    Binary(Bytes),
    Close,
    Ping(Bytes),
    Pong,
}

/// Wraps a relayed [`MeshStream`] as a [`WsSocket`] carrier for the home-side
/// accept path.
pub(in crate::server) struct MeshCarrier {
    stream: MeshStream,
}

impl MeshCarrier {
    pub(in crate::server) fn new(stream: MeshStream) -> Self {
        Self { stream }
    }
}

impl WsSocket for MeshCarrier {
    type Msg = MeshMsg;
    type Reader = RecvStream;
    type Writer = SendStream;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        (self.stream.recv, self.stream.send)
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<MeshMsg>> {
        match reader.read_chunk(MESH_READ_CHUNK, true).await {
            Ok(Some(chunk)) => Ok(Some(MeshMsg::Binary(chunk.bytes))),
            // Clean FIN from the peer: the relayed carrier ended.
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::Error::from(e).context("mesh relay stream read failure")),
        }
    }

    async fn send(writer: &mut Self::Writer, msg: MeshMsg) -> Result<()> {
        match msg {
            MeshMsg::Binary(bytes) => writer
                .write_all(&bytes)
                .await
                .context("mesh relay stream write failure"),
            // Finish signals a clean end of the relayed carrier to the peer.
            MeshMsg::Close => {
                let _ = writer.finish();
                Ok(())
            },
            // No keepalive frames traverse the mesh; QUIC handles liveness.
            MeshMsg::Ping(_) | MeshMsg::Pong => Ok(()),
        }
    }

    async fn finish(writer: &mut Self::Writer) {
        let _ = writer.finish();
    }

    async fn flush(_writer: &mut Self::Writer) -> Result<()> {
        // No buffered control frames: writes go straight to the QUIC stream.
        Ok(())
    }

    fn is_h3() -> bool {
        // QUIC-backed like the H3 carrier: suppress server-originated Ping and
        // pong-deadline reaping; QUIC keep-alive detects a dead peer.
        true
    }

    fn classify(msg: MeshMsg) -> WsFrame {
        match msg {
            MeshMsg::Binary(b) => WsFrame::Binary(b),
            MeshMsg::Close => WsFrame::Close,
            MeshMsg::Ping(p) => WsFrame::Ping(p),
            MeshMsg::Pong => WsFrame::Pong,
        }
    }

    fn binary_msg(data: Bytes) -> MeshMsg {
        MeshMsg::Binary(data)
    }
    fn close_msg() -> MeshMsg {
        MeshMsg::Close
    }
    fn close_try_again_msg() -> MeshMsg {
        // No downstream client to bounce a 1013 to on the mesh; a close is the
        // faithful signal — the edge surfaces retry semantics to the client.
        MeshMsg::Close
    }
    fn ping_msg() -> MeshMsg {
        MeshMsg::Ping(Bytes::new())
    }
    fn pong_msg(_payload: Bytes) -> MeshMsg {
        MeshMsg::Pong
    }
    fn binary_len(msg: &MeshMsg) -> Option<usize> {
        match msg {
            MeshMsg::Binary(b) => Some(b.len()),
            _ => None,
        }
    }
    fn msg_len(msg: &MeshMsg) -> usize {
        match msg {
            MeshMsg::Binary(b) => b.len(),
            MeshMsg::Ping(p) => p.len(),
            MeshMsg::Close | MeshMsg::Pong => 0,
        }
    }

    fn make_udp_response_sender(
        _tx: mpsc::Sender<Self::Msg>,
        _protocol: Protocol,
        _app_protocol: AppProtocol,
        _scheme: PaddingScheme,
        _monitor: Option<Arc<ThroughputMonitor>>,
    ) -> UdpResponseSender {
        // UDP relay over the mesh lands in a later 5c sub-phase; the TCP /
        // VLESS-TCP dispatch never builds a UDP MeshCarrier, so this is
        // unreachable today.
        unimplemented!("mesh UDP relay is not yet supported (TCP/VLESS-TCP only)")
    }
}

#[cfg(test)]
#[path = "tests/mesh_carrier.rs"]
mod tests;
