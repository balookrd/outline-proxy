//! Transport-agnostic framing primitives for VLESS / Shadowsocks payloads.
//!
//! Two orthogonal traits cover the shapes the protocol layer needs:
//!
//!   * [`FrameSink`] / [`FrameSource`] — byte-chunk pipe used by VLESS TCP.
//!     Chunk boundaries are an implementation detail; the protocol layer
//!     concatenates and re-frames as needed.
//!
//!   * [`DatagramChannel`] — packet-oriented pipe with preserved boundaries,
//!     used by VLESS UDP and Shadowsocks UDP.
//!
//! Concrete implementations live alongside (`ws.rs` for WebSocket;
//! `quic.rs` once the QUIC transport lands). Transport-internal control
//! traffic (WS Ping/Pong, idle timers, Close-frame detection) is fully
//! hidden inside the impls — the protocol layer never sees a `Message`.
//!
//! Construction is paired: WS-flavoured sink + source are built together
//! from a single `TransportStream` so the source can route inbound Ping
//! payloads back into the sink's writer task as Pongs.

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

/// Sender half of a byte-chunk pipe. Chunk boundaries are not preserved by
/// the receiving end — implementations may split or coalesce — but a single
/// `send_frame` MUST be delivered atomically (one WS Binary frame, one QUIC
/// `write_all` etc.) so VLESS request-header framing stays intact.
#[async_trait]
pub trait FrameSink: Send + Sync + 'static {
    async fn send_frame(&mut self, data: Bytes) -> Result<()>;
    /// Cleanly tear down the underlying transport. Idempotent.
    async fn close(&mut self) -> Result<()>;
}

/// Receiver half of a byte-chunk pipe. Returns `Ok(None)` on clean EOF and
/// `Err(_)` on transport failure. Implementations are responsible for
/// hiding transport-internal control traffic (Ping replies, idle timers,
/// Close-frame detection) — callers see only payload bytes.
#[async_trait]
pub trait FrameSource: Send + Sync + 'static {
    async fn recv_frame(&mut self) -> Result<Option<Bytes>>;
    /// Whether the last `recv_frame` error / EOF was a clean teardown
    /// (peer-initiated Close, EOF on idle stream) versus a runtime fault.
    /// Read by the proxy/uplink classifiers to decide whether to mark the
    /// uplink down.
    fn closed_cleanly(&self) -> bool;
    /// Installs a handler for out-of-band carrier control signals (e.g. a
    /// server-initiated downstream-throttle notice). Default no-op: only the
    /// padding-aware WS source recognises such signals; every other source
    /// ignores the call so callers can wire it unconditionally.
    fn set_throttle_handle(&mut self, _handle: crate::ThrottleSignalHandle) {}
}

/// Holds a channel's outbound packets on its stream until the protocol above
/// opens it. VLESS-UDP needs it: its first packet carries the request header,
/// which must ride the stream, and the server takes datagrams only once the
/// client has read its response header — so the VLESS layer opens the gate
/// when it parses that header, not on whatever inbound packet comes first (a
/// cover frame on a padded path may precede it).
#[derive(Debug, Default)]
pub(crate) struct DatagramGate(std::sync::atomic::AtomicBool);

impl DatagramGate {
    pub(crate) fn open(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg_attr(
        all(not(feature = "h3"), not(test)),
        expect(dead_code, reason = "only the HTTP/3 datagram channel reads the gate")
    )]
    pub(crate) fn is_open(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Where a received packet came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketSource {
    /// The channel's own carrier stream: a WS Binary frame or an XHTTP body
    /// chunk, which may continue a record an earlier one began.
    Stream,
    /// An HTTP/3 datagram bound to the stream: always one whole packet.
    Datagram,
}

/// Bidirectional packet-oriented channel. Each `send_datagram` yields
/// exactly one packet on the wire; each `recv_datagram` returns one.
/// Shared (`&self`) so both halves can be held by the protocol layer
/// without splitting.
#[async_trait]
pub trait DatagramChannel: Send + Sync + 'static {
    async fn send_datagram(&self, data: Bytes) -> Result<()>;
    /// `Ok(None)` on clean EOF, `Err` on transport failure.
    async fn recv_datagram(&self) -> Result<Option<Bytes>>;
    /// [`Self::recv_datagram`], plus where the packet came from. A protocol
    /// that reassembles records out of its stream (VLESS-UDP over an XHTTP
    /// byte stream) must keep a packet that bypassed the stream out of that
    /// reassembly. Default: every packet came from the stream.
    async fn recv_datagram_with_source(&self) -> Result<Option<(PacketSource, Bytes)>> {
        Ok(self
            .recv_datagram()
            .await?
            .map(|packet| (PacketSource::Stream, packet)))
    }
    /// Bytes a payload may take to go out as one datagram right now, when this
    /// channel sends datagrams at all; `None` means every packet rides the
    /// stream. A hint for framing (padding is cut to fit it): `send_datagram`
    /// still checks, since the room can shrink before the send.
    fn datagram_room(&self) -> Option<usize> {
        None
    }
    /// Idempotent.
    async fn close(&self);
}
