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
//!
//! [`MeshUdpCarrier`] is the SS-UDP counterpart. It shares the same control
//! semantics but frames the body as length-delimited datagrams (see
//! [`crate::server::cluster::mesh::read_datagram`]): one `Binary` frame is one
//! SS-UDP packet, so `recv` reads exactly one datagram and `send` writes one,
//! preserving the packet boundary a raw byte splice would corrupt.

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use metrics::Counter;
use outline_wire::padding::PaddingScheme;
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc;

use super::carrier_padding;
use super::throughput_monitor::ThroughputMonitor;
use super::ws_socket::{WsFrame, WsSocket};
use crate::metrics::{AppProtocol, Protocol};
use crate::server::cluster::mesh::{MeshStream, read_datagram, write_datagram};
use crate::server::nat::{ResponseSender, UdpResponseSender};

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

/// Home-side read half: the mesh recv stream plus the `up` byte counter
/// (`outline_ss_mesh_bytes_total{role="home",direction="up"}`), incremented per
/// chunk pulled off the mesh. Bundling the counter with the stream keeps the
/// static `WsSocket::recv` able to account bytes without a `&self`.
pub(in crate::server) struct MeshCarrierRead {
    stream: RecvStream,
    up: Counter,
}

/// Home-side write half: the mesh send stream plus the `down` byte counter
/// (`outline_ss_mesh_bytes_total{role="home",direction="down"}`).
pub(in crate::server) struct MeshCarrierWrite {
    stream: SendStream,
    down: Counter,
}

/// Wraps a relayed [`MeshStream`] as a [`WsSocket`] carrier for the home-side
/// accept path.
pub(in crate::server) struct MeshCarrier {
    stream: MeshStream,
    up: Counter,
    down: Counter,
}

impl MeshCarrier {
    /// `up`/`down` are the pre-resolved `role="home"` byte counters (up = bytes
    /// read off the mesh, down = bytes written back onto it), from
    /// [`crate::metrics::Metrics::mesh_bytes_counter`].
    pub(in crate::server) fn new(stream: MeshStream, up: Counter, down: Counter) -> Self {
        Self { stream, up, down }
    }
}

impl WsSocket for MeshCarrier {
    type Msg = MeshMsg;
    type Reader = MeshCarrierRead;
    type Writer = MeshCarrierWrite;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        (
            MeshCarrierRead { stream: self.stream.recv, up: self.up },
            MeshCarrierWrite {
                stream: self.stream.send,
                down: self.down,
            },
        )
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<MeshMsg>> {
        match reader.stream.read_chunk(MESH_READ_CHUNK, true).await {
            Ok(Some(chunk)) => {
                reader.up.increment(chunk.bytes.len() as u64);
                Ok(Some(MeshMsg::Binary(chunk.bytes)))
            },
            // Clean FIN from the peer: the relayed carrier ended.
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::Error::from(e).context("mesh relay stream read failure")),
        }
    }

    async fn send(writer: &mut Self::Writer, msg: MeshMsg) -> Result<()> {
        match msg {
            MeshMsg::Binary(bytes) => {
                writer
                    .stream
                    .write_all(&bytes)
                    .await
                    .context("mesh relay stream write failure")?;
                writer.down.increment(bytes.len() as u64);
                Ok(())
            },
            // Finish signals a clean end of the relayed carrier to the peer.
            MeshMsg::Close => {
                let _ = writer.stream.finish();
                Ok(())
            },
            // No keepalive frames traverse the mesh; QUIC handles liveness.
            MeshMsg::Ping(_) | MeshMsg::Pong => Ok(()),
        }
    }

    async fn finish(writer: &mut Self::Writer) {
        let _ = writer.stream.finish();
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
        // The byte-stream `MeshCarrier` serves the TCP / VLESS-TCP dispatch,
        // which never builds a UDP sender; SS-UDP uses `MeshUdpCarrier`.
        unimplemented!("MeshCarrier is byte-stream only; SS-UDP uses MeshUdpCarrier")
    }
}

/// Home-side SS-UDP read half: the mesh recv stream plus the `up` byte and
/// datagram counters (`role="home",direction="up"`), incremented per datagram
/// de-framed off the mesh.
pub(in crate::server) struct MeshUdpCarrierRead {
    stream: RecvStream,
    bytes_up: Counter,
    datagrams_up: Counter,
}

/// Home-side SS-UDP write half: the mesh send stream plus the `down` byte and
/// datagram counters (`role="home",direction="down"`).
pub(in crate::server) struct MeshUdpCarrierWrite {
    stream: SendStream,
    bytes_down: Counter,
    datagrams_down: Counter,
}

/// Wraps a relayed [`MeshStream`] as a [`WsSocket`] carrier for the home-side
/// SS-UDP accept path. Unlike [`MeshCarrier`], the body is length-delimited
/// datagrams: `recv` reads exactly one datagram and reports it as one `Binary`
/// frame, `send` frames one `Binary` back — preserving the per-packet boundary
/// SS-UDP's AEAD relies on. Control/close semantics are identical to the
/// byte-stream carrier.
pub(in crate::server) struct MeshUdpCarrier {
    stream: MeshStream,
    bytes_up: Counter,
    bytes_down: Counter,
    datagrams_up: Counter,
    datagrams_down: Counter,
}

impl MeshUdpCarrier {
    /// Counters are the pre-resolved `role="home"` byte and datagram handles for
    /// each direction (up = de-framed off the mesh, down = framed onto it), from
    /// [`crate::metrics::Metrics::mesh_bytes_counter`] /
    /// [`crate::metrics::Metrics::mesh_datagrams_counter`].
    pub(in crate::server) fn new(
        stream: MeshStream,
        bytes_up: Counter,
        bytes_down: Counter,
        datagrams_up: Counter,
        datagrams_down: Counter,
    ) -> Self {
        Self {
            stream,
            bytes_up,
            bytes_down,
            datagrams_up,
            datagrams_down,
        }
    }
}

impl WsSocket for MeshUdpCarrier {
    type Msg = MeshMsg;
    type Reader = MeshUdpCarrierRead;
    type Writer = MeshUdpCarrierWrite;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        (
            MeshUdpCarrierRead {
                stream: self.stream.recv,
                bytes_up: self.bytes_up,
                datagrams_up: self.datagrams_up,
            },
            MeshUdpCarrierWrite {
                stream: self.stream.send,
                bytes_down: self.bytes_down,
                datagrams_down: self.datagrams_down,
            },
        )
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<MeshMsg>> {
        // One length-delimited datagram = one Binary frame. A clean stream end
        // at a frame boundary reports the relayed carrier ended.
        let mut buf = Vec::new();
        match read_datagram(&mut reader.stream, &mut buf).await? {
            Some(len) => {
                reader.bytes_up.increment(len as u64);
                reader.datagrams_up.increment(1);
                Ok(Some(MeshMsg::Binary(Bytes::from(buf))))
            },
            None => Ok(None),
        }
    }

    async fn send(writer: &mut Self::Writer, msg: MeshMsg) -> Result<()> {
        match msg {
            // Frame one datagram; the peer's `recv` reconstructs the boundary.
            MeshMsg::Binary(bytes) => {
                write_datagram(&mut writer.stream, &bytes).await?;
                writer.bytes_down.increment(bytes.len() as u64);
                writer.datagrams_down.increment(1);
                Ok(())
            },
            MeshMsg::Close => {
                let _ = writer.stream.finish();
                Ok(())
            },
            MeshMsg::Ping(_) | MeshMsg::Pong => Ok(()),
        }
    }

    async fn finish(writer: &mut Self::Writer) {
        let _ = writer.stream.finish();
    }

    async fn flush(_writer: &mut Self::Writer) -> Result<()> {
        Ok(())
    }

    fn is_h3() -> bool {
        // QUIC-backed like the H3 carrier: suppress server Ping / pong reaping.
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
        tx: mpsc::Sender<Self::Msg>,
        protocol: Protocol,
        app_protocol: AppProtocol,
        scheme: PaddingScheme,
        monitor: Option<Arc<ThroughputMonitor>>,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(MeshUdpResponseSender {
            tx,
            protocol,
            app_protocol,
            padding: scheme,
            monitor,
        }))
    }
}

/// Downlink UDP sender for a home-side relayed SS-UDP session. Mirrors
/// [`super::ws_socket`]'s `WebSocketResponseSender`: it applies the path's
/// carrier padding to each datagram (so the home, not the edge, owns padding —
/// the edge forwards the padded bytes verbatim) and enqueues a `Binary` message
/// that the writer task frames onto the mesh stream.
struct MeshUdpResponseSender {
    tx: mpsc::Sender<MeshMsg>,
    protocol: Protocol,
    app_protocol: AppProtocol,
    /// Carrier-padding scheme for this path; disabled passes the datagram
    /// through unchanged (plain wire, still mesh-framed).
    padding: PaddingScheme,
    /// Per-carrier downstream-throttle monitor; `Some` only on a padded path
    /// with detection on.
    monitor: Option<Arc<ThroughputMonitor>>,
}

impl ResponseSender for MeshUdpResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        if let Some(m) = &self.monitor {
            let used = self.tx.max_capacity().saturating_sub(self.tx.capacity());
            m.note_datagram(data.len(), used, self.tx.max_capacity());
        }
        let framed = carrier_padding::frame_downlink_message(self.padding, data);
        Box::pin(async move { self.tx.send(MeshMsg::Binary(framed)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn app_protocol(&self) -> AppProtocol {
        self.app_protocol
    }
}

#[cfg(test)]
#[path = "tests/mesh_carrier.rs"]
mod tests;
