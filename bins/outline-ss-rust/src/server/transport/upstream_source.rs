//! Where a relay's upstream bytes come from.
//!
//! On a standalone server or a cluster home the relay connects out to the target
//! itself. On a cluster **edge** the home already owns that socket: the edge
//! terminates the client's crypto and exchanges plaintext with the home over the
//! mesh, so the mesh stream takes the upstream's place. Keeping the distinction
//! in one enum — rather than branching inside each carrier — is what lets
//! SS-TCP, VLESS and SS-UDP share the same story.
//!
//! The edge half of the v5 mesh protocol lives here too, because it is exactly
//! the part of the hand-off that has to happen *between* authenticating the
//! client and reading the first upstream byte: the [`UserFrame`] naming the user
//! the edge just authenticated, and the [`UpstreamAckFrame`] the home answers it
//! with. See `server::cluster::mesh::frame` for the full stream layout.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use metrics::Counter;
use quinn::{RecvStream, SendStream, VarInt};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::OwnedSemaphorePermit;

use crate::crypto::MAX_CHUNK_SIZE;
use crate::metrics::Metrics;
use crate::server::cluster::mesh::{
    CloseIntent, CloseReason, MAX_USER_LEN, MeshFraming, MeshShape, MeshStream, PooledRelay,
    UPSTREAM_ACK_FRAME_LEN, UpstreamAckFrame, UserFrame, write_datagram,
};
use crate::server::relay::UpstreamRead;

/// Read granularity of the mesh→client direction on the edge, and the upper
/// bound on a single read from the home: a peer can never drive a larger
/// allocation here however much it sends.
///
/// Pinned to [`MAX_CHUNK_SIZE`] rather than a round 64 KiB, because
/// [`MeshUpstream::try_read_buf`] hands the whole chunk to the relay in one
/// piece. A direct upstream cannot exceed that ceiling — `try_read_buf` on a
/// `TcpStream` fills only the spare capacity the relay reserved — but a chunk
/// read off the mesh is `put_slice`d in whole, so the buffer ends up exactly
/// this long. One byte over and `encrypt_chunk` rejects the chunk outright on an
/// SS-2022 cipher (a legacy cipher would silently split it instead), tearing
/// down the relay. Pinned by
/// `server::tests::relay::a_mesh_sized_chunk_survives_an_ss2022_relay`.
pub(in crate::server) const MESH_UPSTREAM_CHUNK: usize = MAX_CHUNK_SIZE;

/// Where a relay takes its upstream from — byte stream or datagram alike.
pub(in crate::server) enum UpstreamSource {
    /// Connect out to the target from this node.
    Direct,
    /// Read and write application plaintext over a mesh stream to the home that
    /// owns the parked upstream. The edge must not park such a session.
    Mesh(MeshUpstreamSetup),
}

/// An opened — but not yet completed — v5 mesh relay, waiting for the user the
/// edge is about to authenticate.
///
/// The home has already acked the OPEN (which is what released the edge to
/// upgrade its client carrier), so the second phase left to run is the USER
/// frame and the home's resume-continuity prologue. [`Self::attach`] performs
/// both and yields the two halves the relay uses.
pub(in crate::server) struct MeshUpstreamSetup {
    stream: MeshStream,
    /// Pool permit for the relay stream, released once **both** halves are
    /// dropped — the relay's real lifetime, since the two halves end
    /// independently.
    permit: Arc<OwnedSemaphorePermit>,
    /// Whether the OPEN advertised the ACK-PREFIX capability, and therefore
    /// whether the home prefixes the downlink with an [`UpstreamAckFrame`].
    ack_prefix: bool,
    /// Bounds every mesh operation: the setup exchange below, and each uplink
    /// write once the relay runs.
    budget: Duration,
    /// The shape of the park the home acked — how this relay's body is framed,
    /// and (on a VLESS carrier, where the OPEN could not say) which client
    /// commands may use it at all.
    shape: MeshShape,
    /// Counters are resolved at attach, not here: a VLESS relay does not know
    /// its transport label until the command decides it, and a `role="edge"`
    /// series must name the transport actually on the wire.
    metrics: Arc<Metrics>,
}

/// The `role="edge"` counter handles one relay feeds, resolved once at setup.
///
/// `up` is client→mesh (toward the home) and `down` is mesh→client, the same
/// series the v4 splice fed — so a relay that never carries downlink is still
/// visible as `down = 0`. The datagram pair is incremented only by the SS-UDP
/// framing; a byte-stream relay leaves it untouched.
struct MeshRelayCounters {
    up_bytes: Counter,
    down_bytes: Counter,
    up_datagrams: Counter,
    down_datagrams: Counter,
}

impl MeshRelayCounters {
    /// `framing` is the one the acked [`MeshShape`] resolves to; a shape with no
    /// framing carries no body and never reaches a counter, so it labels as
    /// `tcp` rather than inventing a series.
    fn new(framing: Option<MeshFraming>, metrics: &Metrics) -> Self {
        let transport = match framing {
            Some(MeshFraming::Tcp) | None => "tcp",
            Some(MeshFraming::Udp) => "udp",
        };
        Self {
            up_bytes: metrics.mesh_bytes_counter("edge", "up", transport),
            down_bytes: metrics.mesh_bytes_counter("edge", "down", transport),
            up_datagrams: metrics.mesh_datagrams_counter("edge", "up"),
            down_datagrams: metrics.mesh_datagrams_counter("edge", "down"),
        }
    }
}

/// The halves of an attached mesh upstream, plus what the home said about it.
pub(in crate::server::transport) struct MeshUpstreamHalves {
    pub(in crate::server::transport) writer: UpstreamWriter,
    pub(in crate::server::transport) reader: MeshUpstream,
    /// How many uplink bytes the home's upstream socket has taken over this
    /// session's whole life. `0` when the OPEN did not advertise ACK-PREFIX
    /// (the home then sends no prologue).
    pub(in crate::server::transport) upstream_acked: u64,
}

/// The datagram-shaped halves of an attached mesh upstream: a datagram edge's
/// stand-in for the socket the home owns — a NAT entry for SS-UDP, a single
/// connected socket for VLESS-UDP.
///
/// Handed over raw rather than behind a `WsSocket`-shaped carrier adapter
/// because the two directions are driven by different owners — the relay loop
/// writes the uplink inline, a pump task reads the downlink — and because the
/// edge closes each half deliberately (`finish` on the uplink,
/// `STOP_SENDING(CarrierEnded)` on the downlink) rather than through a carrier's
/// control frames.
pub(in crate::server::transport) struct MeshDatagramHalves {
    pub(in crate::server::transport) send: SendStream,
    pub(in crate::server::transport) recv: RecvStream,
    /// Bounds one mesh write, as on the byte-stream half.
    pub(in crate::server::transport) budget: Duration,
    pub(in crate::server::transport) up_bytes: Counter,
    pub(in crate::server::transport) up_datagrams: Counter,
    pub(in crate::server::transport) down_bytes: Counter,
    pub(in crate::server::transport) down_datagrams: Counter,
    /// Pool permit for the relay stream, released once **both** halves are
    /// dropped — the relay's real lifetime, since the two end independently.
    pub(in crate::server::transport) permit: Arc<OwnedSemaphorePermit>,
}

impl MeshUpstreamSetup {
    /// Wraps an opened relay. `ack_prefix` must be the flag the OPEN carried —
    /// it decides whether the home's prologue is on the wire at all, so reading
    /// it wrong desynchronises the stream. `shape` must likewise be the one the
    /// home acked, since it is what says how the body is framed.
    pub(in crate::server) fn new(
        pooled: PooledRelay,
        ack_prefix: bool,
        budget: Duration,
        shape: MeshShape,
        metrics: &Arc<Metrics>,
    ) -> Self {
        let (send, recv, permit) = pooled.into_parts();
        Self {
            stream: MeshStream { send, recv },
            permit: Arc::new(permit),
            ack_prefix,
            budget,
            shape,
            metrics: Arc::clone(metrics),
        }
    }

    /// The shape of the park the home is holding for this relay.
    ///
    /// The VLESS dispatch asks before it commits: only a command whose upstream
    /// *is* this shape may attest a user, and anything else releases the relay
    /// with the home's park untouched.
    pub(in crate::server::transport) fn shape(&self) -> MeshShape {
        self.shape
    }

    /// Abandons an opened relay without ever attesting a user, resetting both
    /// halves so the home learns immediately instead of waiting out its
    /// USER-frame deadline with a relay slot held.
    ///
    /// The one caller is the VLESS edge: it opens the relay before it can read
    /// the client's first frame, and only then learns which command it is
    /// serving. When that command's upstream shape is not the one the home acked
    /// ([`Self::shape`]) — a `Tcp` command on a UDP-shaped park, a `Mux` one on
    /// a byte-stream park — the edge serves the session locally, and it must get
    /// out *before* [`Self::attach`], because the USER frame is what makes the
    /// home consume its park. Leaving the setup to drop would eventually say the same thing —
    /// the home's frame read fails either way — but not until the session ends,
    /// and this setup owns a pool permit: a long-lived mux or UDP session would
    /// pin an edge relay slot for its whole life, and a home relay slot until the
    /// USER-frame deadline, for a relay neither side will ever use.
    pub(in crate::server::transport) fn refuse(self) {
        let MeshUpstreamSetup {
            stream: MeshStream { mut send, mut recv },
            ..
        } = self;
        let code = VarInt::from_u32(CloseReason::Abort.code());
        // Both fail only on a stream the peer has already torn down, where
        // there is nothing left to tell it.
        let _ = send.reset(code);
        let _ = recv.stop(code);
    }

    /// The second phase both framings share: attests `user` to the home and
    /// consumes the continuity prologue it answers with, leaving the stream
    /// positioned on the first body byte (or datagram).
    ///
    /// Bounded by the health budget in both directions — an unresponsive home
    /// must not pin a client carrier that has already been upgraded.
    async fn exchange(
        send: &mut SendStream,
        recv: &mut RecvStream,
        user: &str,
        ack_prefix: bool,
        budget: Duration,
    ) -> Result<u64> {
        // The frame's length is a single byte, so an over-long name would wrap
        // rather than fail. The home rejects anything past this bound anyway.
        if user.len() > MAX_USER_LEN {
            bail!("mesh USER frame user name too long: {}", user.len());
        }
        let frame = UserFrame { user: user.to_string() }.encode();
        tokio::time::timeout(budget, send.write_all(&frame))
            .await
            .context("timed out sending the mesh USER frame")?
            .context("sending the mesh USER frame")?;

        if !ack_prefix {
            return Ok(0);
        }
        let mut buf = [0u8; UPSTREAM_ACK_FRAME_LEN];
        tokio::time::timeout(budget, recv.read_exact(&mut buf))
            .await
            .context("timed out reading the mesh upstream-ack frame")?
            .context("reading the mesh upstream-ack frame")?;
        Ok(UpstreamAckFrame::parse(&buf)?.upstream_acked)
    }

    /// Completes the v5 hand-off for a byte-stream relay: attests `user` to the
    /// home and consumes the continuity prologue it answers with.
    pub(in crate::server::transport) async fn attach(
        self,
        user: &str,
    ) -> Result<MeshUpstreamHalves> {
        let MeshUpstreamSetup {
            stream: MeshStream { mut send, mut recv },
            permit,
            ack_prefix,
            budget,
            shape,
            metrics,
        } = self;
        let counters = MeshRelayCounters::new(shape.framing(), &metrics);
        let upstream_acked = Self::exchange(&mut send, &mut recv, user, ack_prefix, budget).await?;

        Ok(MeshUpstreamHalves {
            writer: UpstreamWriter::Mesh {
                send,
                budget,
                bytes: counters.up_bytes,
                _permit: Arc::clone(&permit),
            },
            reader: MeshUpstream {
                recv: tokio::sync::Mutex::new(recv),
                pending: parking_lot::Mutex::new(None),
                eof: AtomicBool::new(false),
                bytes: counters.down_bytes,
                _permit: permit,
            },
            upstream_acked,
        })
    }

    /// Completes the v5 hand-off for a **datagram** relay — SS-UDP or VLESS-UDP —
    /// yielding the raw stream halves the edge frames packets onto.
    ///
    /// Identical second phase to [`Self::attach`] — the same USER frame, and the
    /// same `ack_prefix`-gated prologue, which must be consumed whenever the flag
    /// was set or the very first datagram's length prefix would be read out of
    /// the frame's bytes. The reported offset is discarded: a datagram session
    /// acknowledges no uplink byte offset, and the home says so by reporting `0`.
    pub(in crate::server::transport) async fn attach_datagrams(
        self,
        user: &str,
    ) -> Result<MeshDatagramHalves> {
        let MeshUpstreamSetup {
            stream: MeshStream { mut send, mut recv },
            permit,
            ack_prefix,
            budget,
            shape,
            metrics,
        } = self;
        let counters = MeshRelayCounters::new(shape.framing(), &metrics);
        let _acked = Self::exchange(&mut send, &mut recv, user, ack_prefix, budget).await?;
        Ok(MeshDatagramHalves {
            send,
            recv,
            budget,
            up_bytes: counters.up_bytes,
            up_datagrams: counters.up_datagrams,
            down_bytes: counters.down_bytes,
            down_datagrams: counters.down_datagrams,
            permit,
        })
    }
}

/// The write half a TCP-shaped relay forwards client plaintext to.
///
/// One enum rather than a boxed `AsyncWrite`: parking hands the concrete TCP
/// half to the registry, and only the direct variant can ever be parked.
pub(in crate::server::transport) enum UpstreamWriter {
    /// A real socket to the target, owned by this node.
    Tcp(OwnedWriteHalf),
    /// A mesh stream to the home that owns the target socket.
    Mesh {
        send: SendStream,
        /// Bounds one write to the mesh, not one buffer. When the home stops
        /// draining, the QUIC send window fills and the write blocks; exceeding
        /// the budget means a stalled relay, so the stream is reset with
        /// [`CloseReason::Budget`] — the client reconnects and the home's park
        /// TTL-expires. It measures *progress*, not RTT: a peer that keeps
        /// taking bytes keeps renewing it, so only a full stall trips it. Same
        /// rule the home's `write_uplink_chunk` applies to its own socket.
        budget: Duration,
        bytes: Counter,
        _permit: Arc<OwnedSemaphorePermit>,
    },
}

impl UpstreamWriter {
    /// Writes one plaintext buffer upstream.
    ///
    /// The mesh arm counts every byte the stream took *as it takes it*, rather
    /// than adding the buffer length once the whole write lands: a write that
    /// stalls past the budget is abandoned part-way, and the `role="edge"`
    /// uplink counter must still name the bytes that actually reached the home.
    /// The home's own uplink accounting works the same way.
    pub(in crate::server::transport) async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            UpstreamWriter::Tcp(writer) => writer.write_all(buf).await,
            UpstreamWriter::Mesh { send, budget, bytes, .. } => {
                let mut written = 0usize;
                while written < buf.len() {
                    match tokio::time::timeout(*budget, send.write(&buf[written..])).await {
                        // A stream that takes nothing is not going to take the
                        // rest either; looping on it would spin.
                        Ok(Ok(0)) => {
                            return Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "mesh relay uplink write accepted no bytes",
                            ));
                        },
                        Ok(Ok(n)) => {
                            written += n;
                            bytes.increment(n as u64);
                        },
                        Ok(Err(error)) => return Err(io::Error::other(error)),
                        Err(_elapsed) => {
                            // Stalled past the budget: the home is not draining.
                            // Reset rather than finish, so the home reads a
                            // failure instead of a clean end of the request body.
                            let _ = send.reset(VarInt::from_u32(CloseReason::Budget.code()));
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "mesh relay stalled past the health budget",
                            ));
                        },
                    }
                }
                Ok(())
            },
        }
    }

    /// Ends this half: a TCP half-close for a direct upstream, a QUIC FIN for a
    /// mesh one.
    ///
    /// The FIN is deliberate — a reset would drop still-unacked request-body
    /// bytes, which is exactly what the home's re-park is meant to preserve. It
    /// carries no code, so the *reason* rides the `STOP_SENDING` the mesh read
    /// half applies when it drops; see [`MeshUpstream`].
    pub(in crate::server::transport) async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            UpstreamWriter::Tcp(writer) => writer.shutdown().await,
            UpstreamWriter::Mesh { send, .. } => {
                send.finish().map_err(io::Error::other)?;
                Ok(())
            },
        }
    }

    /// Whether this upstream lives on another node. A relayed session must never
    /// be parked here: the socket the park would hand on is not ours.
    pub(in crate::server::transport) fn is_mesh(&self) -> bool {
        matches!(self, UpstreamWriter::Mesh { .. })
    }

    /// The concrete TCP half, for parking. `None` for a mesh upstream.
    pub(in crate::server::transport) fn into_tcp(self) -> Option<OwnedWriteHalf> {
        match self {
            UpstreamWriter::Tcp(writer) => Some(writer),
            UpstreamWriter::Mesh { .. } => None,
        }
    }
}

/// Where a single-target VLESS-UDP session's datagrams go: this node's own
/// connected socket, or the mesh stream to the home that owns one.
///
/// The datagram twin of [`UpstreamWriter`], and separate from it for the same
/// reason the two park shapes are separate — parking hands the concrete
/// `Arc<UdpSocket>` to the registry, and only the direct variant has one. A
/// boundary-preserving `send` per datagram is the whole contract: one client
/// frame is one `send` here and one datagram at the target, and a byte-oriented
/// writer anywhere in that chain would coalesce two packets into one.
pub(in crate::server::transport) enum VlessUdpSink {
    /// A real socket to the target, owned by this node and connected to it.
    Socket(Arc<UdpSocket>),
    /// A mesh stream to the home that owns that socket. Each datagram is
    /// length-framed ([`write_datagram`]) so the boundary survives the hop.
    Mesh {
        send: SendStream,
        /// Bounds one write to the mesh, exactly as on the byte-stream half: a
        /// home that stops draining fills the QUIC send window, and a write past
        /// the budget is a dead relay rather than a slow one.
        budget: Duration,
        bytes: Counter,
        datagrams: Counter,
        _permit: Arc<OwnedSemaphorePermit>,
    },
}

impl VlessUdpSink {
    /// Sends one datagram upstream, whole.
    pub(in crate::server::transport) async fn send(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            VlessUdpSink::Socket(socket) => {
                let sent = socket
                    .send(payload)
                    .await
                    .context("failed to send vless udp datagram upstream")?;
                if sent != payload.len() {
                    bail!("vless udp short send: {sent} of {} bytes", payload.len());
                }
                Ok(())
            },
            VlessUdpSink::Mesh { send, budget, bytes, datagrams, .. } => {
                tokio::time::timeout(*budget, write_datagram(send, payload))
                    .await
                    .context("the mesh relay stalled past the health budget")?
                    .context("relaying a vless udp datagram to the home")?;
                bytes.increment(payload.len() as u64);
                datagrams.increment(1);
                Ok(())
            },
        }
    }

    /// Whether this session's upstream lives on another node. A relayed session
    /// must never be parked here: the socket the park would hand on is not ours.
    pub(in crate::server::transport) fn is_mesh(&self) -> bool {
        matches!(self, VlessUdpSink::Mesh { .. })
    }

    /// The concrete socket, for parking. `None` for a mesh upstream.
    pub(in crate::server::transport) fn parkable_socket(&self) -> Option<&Arc<UdpSocket>> {
        match self {
            VlessUdpSink::Socket(socket) => Some(socket),
            VlessUdpSink::Mesh { .. } => None,
        }
    }

    /// Ends this half at carrier teardown.
    ///
    /// A QUIC FIN on the mesh, and deliberately so: it tells the home the
    /// carrier ended cleanly, which is what makes it re-park the socket instead
    /// of reading a reset as a broken relay. A direct socket has nothing to end
    /// — the caller drops it, and a connected UDP socket has no half-close.
    pub(in crate::server::transport) async fn shutdown(&mut self) {
        if let VlessUdpSink::Mesh { send, .. } = self {
            // Fails only on a stream the home has already torn down, where there
            // is nothing left to tell it.
            let _ = send.finish();
        }
    }
}

/// The read half of a mesh upstream: application plaintext the home relays back
/// from the socket it owns.
///
/// Implements [`UpstreamRead`] over a QUIC stream, whose API has no
/// readiness/non-blocking split. One chunk is therefore buffered here:
/// `readable` pulls it, `try_read_buf` hands it over and reports `WouldBlock`
/// until the next one. That is precisely the shape the relay's greedy drain
/// expects — one awaited read per cycle, then a non-blocking sweep that stops on
/// `WouldBlock`.
///
/// Dropping this half sends a `STOP_SENDING` on the home's downlink, which the
/// home reads as a [`CloseIntent`]. quinn's own drop sends code `0`, and
/// [`CloseIntent::from_code`] maps every unrecognised code to
/// [`CloseIntent::CarrierEnded`] — the conservative reading, and the right one
/// for SS-over-WS: a client that closes its carrier cleanly is usually switching
/// uplinks, not finished (the direct path parks such a session too). An edge
/// that claimed [`CloseIntent::ClientDone`] there would destroy the continuity
/// this whole path exists to provide.
pub(in crate::server::transport) struct MeshUpstream {
    /// Locked only by `readable`, which needs `&self`; `try_read_buf` takes
    /// `&mut self` and reaches the fields directly. Uncontended by
    /// construction — one relay task owns this half.
    recv: tokio::sync::Mutex<RecvStream>,
    /// One chunk read off the mesh and not yet handed to the relay.
    pending: parking_lot::Mutex<Option<Bytes>>,
    eof: AtomicBool,
    bytes: Counter,
    _permit: Arc<OwnedSemaphorePermit>,
}

impl Drop for MeshUpstream {
    /// Says *why* the edge stopped reading, in the one place that always runs:
    /// the client carrier is gone, so this half is dropped whichever way the
    /// session ended. quinn would send `STOP_SENDING(0)` here anyway and the
    /// home would read the same intent from it — spelling it out keeps the
    /// signal on the wire deliberate rather than incidental.
    fn drop(&mut self) {
        // Fails only when the stream is already finished or reset, where there
        // is nothing left to tell the home.
        let _ = self
            .recv
            .get_mut()
            .stop(VarInt::from_u32(CloseIntent::CarrierEnded.code()));
    }
}

impl UpstreamRead for MeshUpstream {
    async fn readable(&self) -> io::Result<()> {
        if self.pending.lock().is_some() || self.eof.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut recv = self.recv.lock().await;
        match recv.read_chunk(MESH_UPSTREAM_CHUNK, true).await {
            Ok(Some(chunk)) => {
                self.bytes.increment(chunk.bytes.len() as u64);
                *self.pending.lock() = Some(chunk.bytes);
                Ok(())
            },
            // The home finished its half: the upstream EOF'd, or it ended the
            // relay. Either way this is end-of-stream for the client.
            Ok(None) => {
                self.eof.store(true, Ordering::Relaxed);
                Ok(())
            },
            Err(error) => Err(io::Error::other(error)),
        }
    }

    fn try_read_buf<B: bytes::BufMut>(&mut self, buf: &mut B) -> io::Result<usize> {
        match self.pending.get_mut().take() {
            Some(bytes) => {
                buf.put_slice(&bytes);
                Ok(bytes.len())
            },
            None if self.eof.load(Ordering::Relaxed) => Ok(0),
            None => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// What the upstream→client relay task hands back when it is cancelled.
///
/// Only a direct TCP upstream is ever parked, so the mesh variant carries
/// nothing: a relayed session's socket lives on the home, and the edge has
/// nothing to hand on.
pub(in crate::server::transport) enum HarvestedUpstream {
    Tcp(OwnedReadHalf),
    Mesh,
}
