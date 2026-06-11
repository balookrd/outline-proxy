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
    /// Idempotent.
    async fn close(&self);
}
