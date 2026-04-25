//! VLESS-UDP over raw QUIC.
//!
//! Wire model (matches the outline-ss-rust server's
//! `transport::raw_quic::vless::handle_udp` / `serve_raw_vless_quic_datagrams`):
//!
//! 1. Per UDP session — to one specific target — the client opens a
//!    bidi stream and writes the standard VLESS request header with
//!    `command = UDP`. The server replies with
//!    `[VERSION(1), addons_len(1)=0x00, session_id_4B_BE]`. The bidi
//!    stays open as a session lifetime anchor: the server reads it
//!    only to detect EOF / abort. Closing the bidi (or the connection)
//!    is the signal to tear down the session on both sides.
//!
//! 2. All inbound and outbound packets ride on QUIC datagrams shared
//!    by every UDP session on the connection, framed as
//!    `session_id_4B_BE || raw_payload`. Demultiplexing is by
//!    [`VlessUdpDemuxer`], one per `SharedQuicConnection`, lazy-spawned
//!    on the first session opened.
//!
//! Unknown / late-arriving session_ids are silently dropped on the
//! receive side, matching the server's `lookup` miss behaviour. This
//! keeps cleanup races benign.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use socks5_proto::TargetAddr;
use tokio::sync::mpsc;
use tracing::debug;

use std::sync::atomic::{AtomicBool, Ordering};

use crate::AbortOnDrop;
use crate::vless::build_vless_udp_request_header;

use super::SharedQuicConnection;
use super::oversize::OversizeStream;

const VLESS_VERSION: u8 = 0x00;
const SESSION_ID_BYTES: usize = 4;
const RESPONSE_HEADER_FIXED: usize = 2 + SESSION_ID_BYTES; // version + addons_len + id
const PER_SESSION_DOWNLINK_CAP: usize = 256;

// ── Demuxer ─────────────────────────────────────────────────────────────────

/// Connection-level dispatcher for incoming VLESS-UDP datagrams.
///
/// Owns one reader task that drains `quinn::Connection::read_datagram`,
/// peels the 4-byte session_id, and forwards the payload to the matching
/// per-session mpsc receiver. The map is `parking_lot::Mutex` because the
/// hot path is brief (HashMap lookup + try_send) and never `.await`s
/// while holding the lock.
pub(crate) struct VlessUdpDemuxer {
    sessions: Arc<Mutex<hashbrown::HashMap<u32, mpsc::Sender<Bytes>>>>,
    /// Strong handle to the parent connection. Held so the demuxer can
    /// lazy-open the oversize-record stream on first oversize send,
    /// without taking the connection as an arg on every call.
    conn: Arc<SharedQuicConnection>,
    /// Set to `true` exactly once via compare_exchange when the
    /// oversize-record reader task is first spawned. Guards against
    /// two concurrent senders both spawning a reader for the same
    /// (lazily-opened) stream.
    oversize_reader_spawned: AtomicBool,
    _reader_task: AbortOnDrop,
    /// Reader task for inbound records on the oversize stream. Owned
    /// by the demuxer (via Mutex) so it can be replaced lazily — at
    /// construction it's None; the first call to `ensure_oversize`
    /// installs it. Held purely to keep the task alive for the
    /// demuxer's lifetime.
    _oversize_reader_task: Mutex<Option<AbortOnDrop>>,
}

impl VlessUdpDemuxer {
    pub(crate) fn spawn(conn: Arc<SharedQuicConnection>) -> Arc<Self> {
        let sessions: Arc<Mutex<hashbrown::HashMap<u32, mpsc::Sender<Bytes>>>> =
            Arc::new(Mutex::new(hashbrown::HashMap::new()));
        let sessions_for_task = Arc::clone(&sessions);
        let conn_for_task = Arc::clone(&conn);
        let reader_task = AbortOnDrop::new(tokio::spawn(async move {
            loop {
                let datagram = match conn_for_task.raw_connection().read_datagram().await {
                    Ok(d) => d,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::ConnectionClosed(_))
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::TimedOut)
                    | Err(quinn::ConnectionError::Reset) => return,
                    Err(error) => {
                        debug!(?error, "vless quic datagram pump aborting");
                        return;
                    }
                };
                if datagram.len() < SESSION_ID_BYTES {
                    debug!(len = datagram.len(), "vless quic datagram too short, dropping");
                    continue;
                }
                let id = u32::from_be_bytes([
                    datagram[0],
                    datagram[1],
                    datagram[2],
                    datagram[3],
                ]);
                let payload = datagram.slice(SESSION_ID_BYTES..);
                let tx_opt = {
                    let guard = sessions_for_task.lock();
                    guard.get(&id).cloned()
                };
                if let Some(tx) = tx_opt {
                    if tx.try_send(payload).is_err() {
                        // Receiver dropped or full — silent drop, the
                        // session reader will observe `recv() == None`
                        // on its own and clean up.
                    }
                } else {
                    // Session unknown / already torn down — match server
                    // behaviour: silent drop.
                }
            }
        }));
        Arc::new(Self {
            sessions,
            conn,
            oversize_reader_spawned: AtomicBool::new(false),
            _reader_task: reader_task,
            _oversize_reader_task: Mutex::new(None),
        })
    }

    fn register(&self, id: u32, tx: mpsc::Sender<Bytes>) {
        self.sessions.lock().insert(id, tx);
    }

    fn unregister(&self, id: u32) {
        self.sessions.lock().remove(&id);
    }

    /// Route one inbound oversize-record into the matching session's
    /// downlink mpsc, mirroring the datagram reader's logic. Records
    /// share the `[session_id_4B || payload]` layout with datagrams,
    /// so the demuxer-side dispatch is identical.
    fn route_record(&self, record: Bytes) {
        if record.len() < SESSION_ID_BYTES {
            debug!(len = record.len(), "vless oversize record too short, dropping");
            return;
        }
        let id = u32::from_be_bytes([record[0], record[1], record[2], record[3]]);
        let payload = record.slice(SESSION_ID_BYTES..);
        let tx_opt = {
            let guard = self.sessions.lock();
            guard.get(&id).cloned()
        };
        if let Some(tx) = tx_opt {
            // Same drop-on-back-pressure semantics as the datagram path:
            // the per-session reader will observe `recv() == None` if
            // the session went away.
            let _ = tx.try_send(payload);
        }
    }

    /// Open (or reuse) the connection-level oversize-record stream and
    /// ensure a reader task is consuming inbound records. Idempotent —
    /// concurrent callers race via `compare_exchange` so the reader is
    /// spawned at most once. Returns `Err` if the negotiated ALPN does
    /// not support oversize records or `open_bi` fails.
    pub(crate) async fn ensure_oversize_stream(self: &Arc<Self>) -> Result<Arc<OversizeStream>> {
        let stream = self.conn.ensure_oversize_stream().await?;
        if self
            .oversize_reader_spawned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let demuxer = Arc::clone(self);
            let stream_for_task = Arc::clone(&stream);
            let task = AbortOnDrop::new(tokio::spawn(async move {
                loop {
                    match stream_for_task.recv_record().await {
                        Ok(Some(record)) => demuxer.route_record(record),
                        Ok(None) => {
                            debug!("vless oversize stream EOF");
                            return;
                        }
                        Err(error) => {
                            debug!(?error, "vless oversize stream reader aborting");
                            return;
                        }
                    }
                }
            }));
            *self._oversize_reader_task.lock() = Some(task);
        }
        Ok(stream)
    }
}

// ── Per-session client ──────────────────────────────────────────────────────

/// Single VLESS UDP session over raw QUIC. Holds the control bidi (kept
/// open as a lifetime anchor), the server-allocated session_id used as
/// the 4-byte datagram prefix, and the per-session mpsc receiver wired
/// through the connection-level demuxer.
///
/// Mirrors the public surface of the WS variant
/// [`crate::vless::VlessUdpTransport`] (`send_packet` /
/// `read_packet` / `close`) so the session-mux / TUN layer stays
/// transport-agnostic.
pub struct VlessUdpQuicSession {
    conn: Arc<SharedQuicConnection>,
    demuxer: Arc<VlessUdpDemuxer>,
    session_id: u32,
    /// Pre-built `session_id_4B` bytes — concatenated with the payload
    /// on every send.
    id_prefix: [u8; 4],
    /// SendStream of the control bidi. Closed (FIN) on `close()` to
    /// signal session teardown to the server.
    ctrl_send: tokio::sync::Mutex<Option<quinn::SendStream>>,
    /// RecvStream of the control bidi. Held alive so the server's read
    /// side stays open; observing EOF here would tell us the server
    /// terminated the session, but we don't currently surface that
    /// (the read_packet path returns `WsClosed` once the demuxer
    /// drops, which happens only when the connection itself dies).
    _ctrl_recv: quinn::RecvStream,
    downlink_rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    closed: std::sync::atomic::AtomicBool,
}

impl VlessUdpQuicSession {
    /// Open one VLESS UDP session on the shared connection. Sends the
    /// VLESS UDP request header on a fresh bidi stream, parses the
    /// `[VERSION, 0x00, session_id_4B_BE]` response, and registers a
    /// receiver with the connection-level demuxer.
    pub async fn open(
        conn: Arc<SharedQuicConnection>,
        uuid: &[u8; 16],
        target: &TargetAddr,
    ) -> Result<Self> {
        let demuxer = Arc::clone(conn.vless_udp_demuxer().await);

        let (mut send, mut recv) = conn
            .open_bidi_stream()
            .await
            .context("failed to open vless udp control bidi stream")?;

        let header = build_vless_udp_request_header(uuid, target);
        send.write_all(&header)
            .await
            .context("failed to write vless udp request header")?;

        let mut response = [0_u8; RESPONSE_HEADER_FIXED];
        let mut filled = 0;
        while filled < RESPONSE_HEADER_FIXED {
            match recv.read(&mut response[filled..]).await {
                Ok(Some(0)) => continue,
                Ok(Some(n)) => filled += n,
                Ok(None) => bail!(
                    "vless udp control bidi closed before response header (got {filled}/{RESPONSE_HEADER_FIXED} bytes)"
                ),
                Err(error) => {
                    return Err(error)
                        .context("failed to read vless udp control bidi response header");
                }
            }
        }
        if response[0] != VLESS_VERSION {
            bail!("vless udp bad response version {:#x}", response[0]);
        }
        if response[1] != 0x00 {
            // Server reports `addons_len = 0` — anything else is an
            // unsupported addon block which we don't parse.
            bail!("vless udp non-zero addons in response not supported (len={})", response[1]);
        }
        let session_id = u32::from_be_bytes([response[2], response[3], response[4], response[5]]);

        let (downlink_tx, downlink_rx) = mpsc::channel::<Bytes>(PER_SESSION_DOWNLINK_CAP);
        demuxer.register(session_id, downlink_tx);

        Ok(Self {
            conn,
            demuxer,
            session_id,
            id_prefix: response[2..6].try_into().expect("4 bytes"),
            ctrl_send: tokio::sync::Mutex::new(Some(send)),
            _ctrl_recv: recv,
            downlink_rx: tokio::sync::Mutex::new(downlink_rx),
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            bail!("vless udp quic session closed");
        }
        let total_len = SESSION_ID_BYTES + payload.len();
        let oversized = self
            .conn
            .max_datagram_size()
            .is_some_and(|max| total_len > max);
        if oversized {
            // Fallback path: the negotiated ALPN may carry oversize
            // records on a dedicated stream. If yes, frame the packet
            // there. If not (legacy ALPN), the packet truly cannot be
            // sent on this connection — surface the typed error so
            // the TUN UDP engine drops it without flapping the uplink.
            if self.conn.supports_oversize_stream() {
                let mut record = Vec::with_capacity(total_len);
                record.extend_from_slice(&self.id_prefix);
                record.extend_from_slice(payload);
                let stream = self
                    .demuxer
                    .ensure_oversize_stream()
                    .await
                    .context("failed to open vless oversize stream for outbound packet")?;
                outline_metrics::add_probe_bytes(
                    "_oversize",
                    "_oversize",
                    "udp",
                    "vless",
                    "outgoing",
                    record.len(),
                );
                return stream
                    .send_record(&record)
                    .await
                    .context("vless oversize record send failed");
            }
            outline_metrics::record_dropped_oversized_udp_packet("outgoing");
            let max = self.conn.max_datagram_size().unwrap_or(0);
            bail!(crate::OversizedUdpDatagram {
                transport: "vless-udp-quic",
                payload_len: total_len,
                limit: max,
            });
        }
        let mut buf = BytesMut::with_capacity(total_len);
        buf.put_slice(&self.id_prefix);
        buf.put_slice(payload);
        self.conn
            .send_datagram(buf.freeze())
            .context("vless udp send_datagram failed")
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        let mut rx = self.downlink_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow!("vless udp quic session downlink closed"))
    }

    pub async fn close(&self) -> Result<()> {
        if self.closed.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        self.demuxer.unregister(self.session_id);
        // FIN the control bidi — the server's read on it returns None
        // and tears down its half of the session.
        let mut send_guard = self.ctrl_send.lock().await;
        if let Some(mut send) = send_guard.take() {
            let _ = send.finish();
        }
        Ok(())
    }
}

impl Drop for VlessUdpQuicSession {
    fn drop(&mut self) {
        // Best-effort unregister — handles the case where `close()` was
        // not called explicitly (e.g. transport-level error). The
        // SendStream's own Drop sends FIN.
        self.demuxer.unregister(self.session_id);
    }
}
