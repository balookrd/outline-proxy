//! QUIC implementations of [`FrameSink`] / [`FrameSource`] /
//! [`DatagramChannel`].
//!
//! TCP-like sessions ride on a single bidi stream per VLESS / SS session;
//! the bidi pair is split into [`QuicFrameSink`] (writes raw bytes) and
//! [`QuicFrameSource`] (reads raw bytes). VLESS reader's accumulator
//! handles arbitrary chunking, so we don't need to preserve message
//! boundaries.
//!
//! UDP-like sessions share the connection's QUIC datagram channel
//! (RFC 9221). Many VLESS-UDP / SS-UDP sessions on the same uplink share
//! one [`QuicDatagramChannel`] — but the underlying connection is a
//! single multiplexed pipe, and sessions distinguish themselves by their
//! own framing (VLESS by per-target session, SS by SOCKS5 atyp prefix).
//! For now `QuicDatagramChannel` is per-session: each VLESS UDP session
//! mux opens a fresh QUIC connection if shared isn't possible — see
//! `quic::dial::connect_quic_uplink` for the sharing semantics.

#![cfg(feature = "quic")]

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;

use crate::frame_io::{DatagramChannel, FrameSink, FrameSource};
use crate::quic::SharedQuicConnection;

// ── Bidi-stream pipe (TCP-like) ─────────────────────────────────────────────

/// QUIC [`FrameSink`] over `quinn::SendStream`. Writes are atomic on the
/// stream (one `write_all` call per `send_frame`) but QUIC does not
/// preserve message boundaries on the receive side — VLESS reader's
/// accumulator absorbs that.
pub struct QuicFrameSink {
    send: Option<quinn::SendStream>,
}

#[async_trait]
impl FrameSink for QuicFrameSink {
    async fn send_frame(&mut self, data: Bytes) -> Result<()> {
        let send = self
            .send
            .as_mut()
            .context("quic frame sink already closed")?;
        send.write_all(&data)
            .await
            .context("failed to write to quic send stream")
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(mut send) = self.send.take() {
            // `finish()` signals FIN on the stream — peer reads see EOF.
            // Errors here mean the connection is gone; ignore.
            let _ = send.finish();
        }
        Ok(())
    }
}

/// QUIC [`FrameSource`] over `quinn::RecvStream`. `recv_frame` returns
/// the next chunk of bytes the peer has flushed; chunks may be split
/// arbitrarily relative to peer writes — that is normal QUIC stream
/// semantics. Returns `Ok(None)` on FIN (clean teardown).
pub struct QuicFrameSource {
    recv: quinn::RecvStream,
    closed_cleanly: bool,
}

#[async_trait]
impl FrameSource for QuicFrameSource {
    async fn recv_frame(&mut self) -> Result<Option<Bytes>> {
        match self.recv.read_chunk(usize::MAX, true).await {
            Ok(Some(chunk)) => Ok(Some(chunk.bytes)),
            Ok(None) => {
                self.closed_cleanly = true;
                Ok(None)
            }
            Err(quinn::ReadError::ClosedStream) => {
                self.closed_cleanly = true;
                Ok(None)
            }
            Err(e) => Err(e).context("failed to read from quic recv stream"),
        }
    }

    fn closed_cleanly(&self) -> bool {
        self.closed_cleanly
    }
}

/// Open a new bidi stream on `conn` and return a paired
/// [`QuicFrameSink`] / [`QuicFrameSource`].
pub async fn open_quic_frame_pair(
    conn: &Arc<SharedQuicConnection>,
) -> Result<(QuicFrameSink, QuicFrameSource)> {
    let (send, recv) = conn.open_bidi_stream().await?;
    let sink = QuicFrameSink { send: Some(send) };
    let source = QuicFrameSource {
        recv,
        closed_cleanly: false,
    };
    Ok((sink, source))
}

// ── Datagram pipe (UDP-like) ───────────────────────────────────────────────

/// QUIC [`DatagramChannel`] over a shared connection. Send / recv are
/// thin wrappers around `quinn::Connection::send_datagram` /
/// `read_datagram`. Note: all sessions sharing the connection see all
/// inbound datagrams — caller is responsible for demuxing (VLESS UDP
/// session mux does this via per-target sessions, each on its own
/// connection; SS UDP carries the destination in-band).
pub struct QuicDatagramChannel {
    conn: Arc<SharedQuicConnection>,
}

impl QuicDatagramChannel {
    pub fn new(conn: Arc<SharedQuicConnection>) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl DatagramChannel for QuicDatagramChannel {
    async fn send_datagram(&self, data: Bytes) -> Result<()> {
        // Fail loudly on oversize: caller must enforce
        // `max_datagram_size()` before reaching this point.
        if let Some(max) = self.conn.max_datagram_size()
            && data.len() > max
        {
            anyhow::bail!(
                "quic datagram too large: {} > {} (peer max_datagram_size)",
                data.len(),
                max
            );
        }
        self.conn.send_datagram(data)
    }

    async fn recv_datagram(&self) -> Result<Option<Bytes>> {
        self.conn.recv_datagram().await
    }

    async fn close(&self) {
        // Datagrams share the connection across many sessions; closing
        // the connection from one session would break the others. The
        // shared connection is torn down only when all `Arc` references
        // are dropped.
    }
}
