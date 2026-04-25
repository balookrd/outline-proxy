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
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::debug;

use crate::AbortOnDrop;
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

/// QUIC [`DatagramChannel`] over a shared connection. Inbound datagrams
/// AND inbound oversize records (when the negotiated ALPN supports the
/// oversize-stream fallback) are merged into one mpsc that
/// `recv_datagram` drains; outbound packets that fit the negotiated
/// `max_datagram_size` go on the QUIC datagram path, larger ones fall
/// back to the connection-level [`crate::quic::OversizeStream`].
///
/// All sessions sharing the connection see all inbound packets — caller
/// is responsible for demuxing (SS UDP carries the destination in-band
/// inside the encrypted payload, so the SS layer above this channel
/// just consumes whatever arrives).
pub struct QuicDatagramChannel {
    conn: Arc<SharedQuicConnection>,
    /// Inbound queue: both the QUIC datagram pump task and (when open)
    /// the oversize-record pump task push into this. `recv_datagram`
    /// drains it.
    inbound_tx: mpsc::UnboundedSender<Result<Bytes>>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<Result<Bytes>>>,
    /// Datagram pump task — drains `conn.recv_datagram()` into
    /// `inbound_tx`. Spawned eagerly at construction; held purely so
    /// it lives as long as the channel.
    _datagram_pump: AbortOnDrop,
    /// Oversize-record pump task — lazy-spawned the first time an
    /// oversize record needs to be sent (`send_datagram` oversize
    /// branch) or the first time the peer opens the oversize stream.
    /// Held in `Mutex<Option>` so the lazy install path can swap it in
    /// without the surrounding code needing `&mut self`.
    _oversize_pump: SyncMutex<Option<AbortOnDrop>>,
    /// Shared flag — flipped exactly once when EITHER the local-open
    /// path (`ensure_oversize_pump`) or the peer-open path (the
    /// `accept_bi` task spawned at construction) first installs the
    /// oversize stream and spawns its record reader. The Arc lets
    /// the accept_bi closure observe the same flag without
    /// borrowing `&self`.
    oversize_pump_spawned: Arc<AtomicBool>,
    /// accept_bi pump that listens for server-initiated oversize-record
    /// streams. Spawned at construction iff the negotiated ALPN
    /// supports oversize records.
    _oversize_accept_task: SyncMutex<Option<AbortOnDrop>>,
}

impl QuicDatagramChannel {
    pub fn new(conn: Arc<SharedQuicConnection>) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Result<Bytes>>();
        let conn_for_pump = Arc::clone(&conn);
        let inbound_tx_for_pump = inbound_tx.clone();
        let datagram_pump = AbortOnDrop::new(tokio::spawn(async move {
            loop {
                match conn_for_pump.recv_datagram().await {
                    Ok(Some(b)) => {
                        if inbound_tx_for_pump.send(Ok(b)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = inbound_tx_for_pump.send(Ok(Bytes::new()));
                        // Connection closed — propagate by dropping
                        // the sender via task exit.
                        return;
                    }
                    Err(error) => {
                        let _ = inbound_tx_for_pump.send(Err(error));
                        return;
                    }
                }
            }
        }));
        let oversize_pump_spawned: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let channel = Self {
            conn: Arc::clone(&conn),
            inbound_tx: inbound_tx.clone(),
            inbound_rx: Mutex::new(inbound_rx),
            _datagram_pump: datagram_pump,
            _oversize_pump: SyncMutex::new(None),
            oversize_pump_spawned: Arc::clone(&oversize_pump_spawned),
            _oversize_accept_task: SyncMutex::new(None),
        };
        // accept_bi pump for server-initiated oversize-record streams:
        // listen on the connection for any incoming bidi, peek 8 bytes
        // for the magic, install the stream + spawn the record reader.
        // Spawned only when the negotiated ALPN advertises oversize
        // support; on legacy `ss` ALPN this path is dormant.
        if conn.supports_oversize_stream() {
            let conn_for_accept = Arc::clone(&conn);
            let inbound_tx_for_accept = inbound_tx;
            let flag_for_accept = Arc::clone(&oversize_pump_spawned);
            let task = AbortOnDrop::new(tokio::spawn(async move {
                let raw = conn_for_accept.raw_connection();
                loop {
                    let (send, mut recv) = match raw.accept_bi().await {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    let mut head = [0u8; crate::quic::OVERSIZE_STREAM_MAGIC.len()];
                    if let Err(error) = tokio::io::AsyncReadExt::read_exact(&mut recv, &mut head)
                        .await
                    {
                        debug!(?error, "accept_bi peek failed for ss oversize stream");
                        continue;
                    }
                    if &head != crate::quic::OVERSIZE_STREAM_MAGIC {
                        debug!(?head, "accept_bi got non-oversize stream from server, ignoring");
                        continue;
                    }
                    let stream = crate::quic::OversizeStream::from_accept_validated(send, recv);
                    let installed = conn_for_accept.install_accepted_oversize_stream(stream);
                    // Spawn record reader if not already running.
                    if flag_for_accept
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        let inbound_tx_for_reader = inbound_tx_for_accept.clone();
                        tokio::spawn(async move {
                            loop {
                                match installed.recv_record().await {
                                    Ok(Some(record)) => {
                                        if inbound_tx_for_reader.send(Ok(record)).is_err() {
                                            return;
                                        }
                                    }
                                    Ok(None) => return,
                                    Err(error) => {
                                        debug!(?error, "ss oversize reader (peer-opened) aborting");
                                        return;
                                    }
                                }
                            }
                        });
                    }
                }
            }));
            *channel._oversize_accept_task.lock() = Some(task);
        }
        channel
    }

    /// Lazy-open the oversize-record stream and spawn its inbound pump
    /// task into the same `inbound_tx` mpsc. Idempotent — both this
    /// call and the accept_bi closure share `oversize_pump_spawned`
    /// so the reader is started at most once across both paths.
    async fn ensure_oversize_pump(&self) -> Result<Arc<crate::quic::OversizeStream>> {
        let stream = self.conn.ensure_oversize_stream().await?;
        if self
            .oversize_pump_spawned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let stream_for_pump = Arc::clone(&stream);
            let inbound_tx = self.inbound_tx.clone();
            let pump = AbortOnDrop::new(tokio::spawn(async move {
                loop {
                    match stream_for_pump.recv_record().await {
                        Ok(Some(record)) => {
                            if inbound_tx.send(Ok(record)).is_err() {
                                return;
                            }
                        }
                        Ok(None) => {
                            debug!("ss oversize stream EOF");
                            return;
                        }
                        Err(error) => {
                            debug!(?error, "ss oversize stream reader aborting");
                            return;
                        }
                    }
                }
            }));
            *self._oversize_pump.lock() = Some(pump);
        }
        Ok(stream)
    }
}

#[async_trait]
impl DatagramChannel for QuicDatagramChannel {
    async fn send_datagram(&self, data: Bytes) -> Result<()> {
        let oversized = self
            .conn
            .max_datagram_size()
            .is_some_and(|max| data.len() > max);
        if oversized {
            if self.conn.supports_oversize_stream() {
                let stream = self.ensure_oversize_pump().await?;
                return stream
                    .send_record(&data)
                    .await
                    .context("ss oversize record send failed");
            }
            outline_metrics::record_dropped_oversized_udp_packet("outgoing");
            let max = self.conn.max_datagram_size().unwrap_or(0);
            anyhow::bail!(crate::OversizedUdpDatagram {
                transport: "ss-udp-quic",
                payload_len: data.len(),
                limit: max,
            });
        }
        self.conn.send_datagram(data)
    }

    async fn recv_datagram(&self) -> Result<Option<Bytes>> {
        let mut rx = self.inbound_rx.lock().await;
        match rx.recv().await {
            Some(Ok(b)) if b.is_empty() => Ok(None),
            Some(Ok(b)) => Ok(Some(b)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    async fn close(&self) {
        // Datagrams share the connection across many sessions; closing
        // the connection from one session would break the others. The
        // shared connection is torn down only when all `Arc` references
        // are dropped.
    }
}
