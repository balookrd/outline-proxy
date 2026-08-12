//! `WsSocket` impl over an XHTTP session pair.
//!
//! Lets the existing `run_vless_relay::<T: WsSocket>` drive a
//! VLESS session whose underlying transport is the GET/POST pair
//! of an XHTTP packet-up handshake. The reader pops in-order
//! uplink chunks from the session ring; the writer enqueues
//! downlink bytes. XHTTP has no on-wire ping framing, so a
//! WebSocket Ping (the relay's keepalive tick) maps to a session
//! `touch()` that holds off idle eviction; Pong is a no-op and
//! Close tears the session down.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use outline_wire::padding::PaddingScheme;
use outline_wire::udp_records::{UdpRecordDecoder, encode_record_into};
use tokio::sync::mpsc;
use tracing::warn;

use super::super::carrier_padding;

use crate::{
    metrics::{AppProtocol, Protocol},
    server::nat::{ResponseSender, UdpResponseSender},
};

use super::super::ws_socket::{WsFrame, WsSocket};
use super::{DownlinkPushError, XhttpSession};

/// Message exchanged on an XHTTP duplex. The variants mirror the
/// subset of `WsMessage` the VLESS relay actually emits: payload
/// bytes, an explicit close, and a `Noop` carrier for the relay's
/// keepalive ticks — there is no XHTTP downlink ping frame, so the
/// tick is consumed server-side as a session `touch()` (see
/// `XhttpDuplex::send`) rather than written to the wire.
#[derive(Debug)]
pub(in crate::server) enum XhttpMsg {
    Binary(Bytes),
    Close,
    Noop,
}

pub(in crate::server) struct XhttpDuplex {
    pub(in crate::server) session: Arc<XhttpSession>,
    /// Datagram record framing negotiated for this session (see
    /// [`outline_wire::udp_records`]). `true` only on an SS-UDP path whose
    /// client advertised `X-Outline-Udp-Records: 1`. XHTTP carries a byte
    /// stream, so without framing an uplink chunk is not a datagram: two
    /// packets coalesce (AEAD tag mismatch) or one arrives halved ("packet too
    /// short"). `false` keeps the historical wire for every other session.
    pub(in crate::server) udp_records: bool,
}

impl XhttpDuplex {
    /// Builds a duplex over `session`, framing datagrams when the session
    /// negotiated it. `spawn_relay` uses this for the SS-UDP arm; the TCP /
    /// VLESS arms construct the struct directly with framing off.
    pub(in crate::server) fn with_udp_records(
        session: Arc<XhttpSession>,
        udp_records: bool,
    ) -> Self {
        Self { session, udp_records }
    }
}

pub(in crate::server) struct XhttpReader {
    session: Arc<XhttpSession>,
    /// Reassembly state when framing is negotiated; `None` keeps `recv`
    /// forwarding raw chunks. Bounded by the `u16` record length.
    records: Option<UdpRecordDecoder>,
    /// Datagrams recovered from the last chunk, not yet returned. One `recv`
    /// yields one datagram, so the relay's per-packet path is unchanged.
    pending: VecDeque<Bytes>,
}

pub(in crate::server) struct XhttpWriter {
    session: Arc<XhttpSession>,
    /// Frames each downlink datagram as its own record when negotiated.
    udp_records: bool,
}

impl WsSocket for XhttpDuplex {
    type Msg = XhttpMsg;
    type Reader = XhttpReader;
    type Writer = XhttpWriter;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        let reader = XhttpReader {
            session: Arc::clone(&self.session),
            records: self.udp_records.then(UdpRecordDecoder::new),
            pending: VecDeque::new(),
        };
        let writer = XhttpWriter {
            session: self.session,
            udp_records: self.udp_records,
        };
        (reader, writer)
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<XhttpMsg>> {
        loop {
            // A datagram recovered from an earlier chunk goes out first: one
            // `recv` is one datagram, whatever the carrier's chunking was.
            if let Some(record) = reader.pending.pop_front() {
                return Ok(Some(XhttpMsg::Binary(record)));
            }
            if let Some(chunk) = reader.session.pop_uplink_ready() {
                match take_records(&mut reader.records, &mut reader.pending, chunk) {
                    Some(msg) => return Ok(Some(msg)),
                    // The chunk completed no record — read the next one.
                    None => continue,
                }
            }
            if reader.session.is_closed() || reader.session.uplink_eof() {
                return Ok(None);
            }
            // Register interest *before* the recheck so a concurrent
            // POST that lands between the pop_uplink_ready and the
            // notify subscription cannot lose the wake-up.
            let notified = reader.session.uplink_notify.notified();
            if let Some(chunk) = reader.session.pop_uplink_ready() {
                match take_records(&mut reader.records, &mut reader.pending, chunk) {
                    Some(msg) => return Ok(Some(msg)),
                    None => continue,
                }
            }
            if reader.session.is_closed() || reader.session.uplink_eof() {
                return Ok(None);
            }
            notified.await;
        }
    }

    async fn send(writer: &mut Self::Writer, msg: XhttpMsg) -> Result<()> {
        let msg = match msg {
            // Framing negotiated: length-prefix the datagram so the client can
            // recover the boundary from whatever body chunking the carrier
            // (and any CDN on the path) produces.
            XhttpMsg::Binary(data) if writer.udp_records => match frame_datagram(&data) {
                Some(record) => XhttpMsg::Binary(record),
                // Past the `u16` record ceiling — no real UDP datagram gets
                // here. Drop it rather than tearing down a healthy session.
                None => return Ok(()),
            },
            other => other,
        };
        match msg {
            XhttpMsg::Binary(data) => match writer.session.push_downlink(data).await {
                Ok(()) => Ok(()),
                Err(DownlinkPushError::Closed) => Err(anyhow!("xhttp session closed")),
            },
            XhttpMsg::Close => {
                writer.session.close();
                Ok(())
            },
            // Keepalive tick from `run_vless_relay`. XHTTP has no
            // on-wire Ping frame, so we cannot reset the *client's*
            // datagram idle watchdog from here — but we can keep the
            // *server* session alive: bump the keepalive clock so the
            // registry janitor does not evict an idle-but-live relay
            // out from under us. Without this a UDP datagram channel
            // with a lull longer than `SESSION_IDLE_EVICTION` (DNS
            // between lookups, a quiet QUIC connection) is torn down
            // mid-session and the client sees a spurious `ws closed`.
            // Deliberately `touch_keepalive`, not `touch_progress`: a
            // keepalive proves the carrier is alive but not that the
            // downlink is draining, so a stuck GET consumer cannot ride
            // keepalives past idle eviction (see
            // `XhttpSession::is_evictable`). The lower transport (h2/h3
            // keepalive) keeps the carrier itself live, so the client
            // side does not need a frame.
            XhttpMsg::Noop => {
                writer.session.touch_keepalive();
                Ok(())
            },
        }
    }

    async fn finish(writer: &mut Self::Writer) {
        writer.session.close();
    }

    async fn flush(_writer: &mut Self::Writer) -> Result<()> {
        // XHTTP has no on-wire control frames; its session is kept warm
        // out-of-band via `touch()` on the keepalive tick (see
        // `XhttpMsg::Noop`), so there is nothing buffered to flush.
        Ok(())
    }

    fn is_h3() -> bool {
        // XHTTP rides h2/h3 underneath, but its keepalive is handled
        // out-of-band via session `touch()` and it emits no WS Ping, so the
        // H3-Ping hazard does not apply — report `false` so the relay keeps
        // its normal keepalive-tick bookkeeping.
        false
    }

    fn classify(msg: XhttpMsg) -> WsFrame {
        match msg {
            XhttpMsg::Binary(b) => WsFrame::Binary(b),
            XhttpMsg::Close => WsFrame::Close,
            // Pong is a benign no-op for the relay; we never read
            // Noop messages off the wire (recv only emits Binary or
            // None), so this branch is theoretical.
            XhttpMsg::Noop => WsFrame::Pong,
        }
    }

    fn binary_msg(data: Bytes) -> XhttpMsg {
        XhttpMsg::Binary(data)
    }
    fn close_msg() -> XhttpMsg {
        XhttpMsg::Close
    }
    fn close_try_again_msg() -> XhttpMsg {
        // XHTTP has no equivalent of RFC 6455 close code 1013. Best
        // we can do is close the session and let the client decide
        // whether to retry — same wire effect as a generic close.
        XhttpMsg::Close
    }
    fn ping_msg() -> XhttpMsg {
        XhttpMsg::Noop
    }
    fn pong_msg(_payload: Bytes) -> XhttpMsg {
        XhttpMsg::Noop
    }
    fn binary_len(msg: &XhttpMsg) -> Option<usize> {
        if let XhttpMsg::Binary(b) = msg {
            Some(b.len())
        } else {
            None
        }
    }
    fn msg_len(msg: &XhttpMsg) -> usize {
        match msg {
            XhttpMsg::Binary(b) => b.len(),
            XhttpMsg::Close | XhttpMsg::Noop => 0,
        }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<XhttpMsg>,
        _protocol: Protocol,
        app_protocol: AppProtocol,
        scheme: PaddingScheme,
        monitor: Option<Arc<crate::server::transport::throughput_monitor::ThroughputMonitor>>,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(XhttpUdpResponseSender {
            tx,
            app_protocol,
            padding: scheme,
            monitor,
        }))
    }
}

/// Feeds one uplink chunk through the reader's record decoder and returns the
/// first datagram it completed (the rest queue in `pending`). `None` means the
/// chunk held no complete record yet — the caller reads on. With framing off
/// the chunk is forwarded unchanged, which is the historical behaviour.
fn take_records(
    records: &mut Option<UdpRecordDecoder>,
    pending: &mut VecDeque<Bytes>,
    chunk: Bytes,
) -> Option<XhttpMsg> {
    let Some(decoder) = records.as_mut() else {
        return Some(XhttpMsg::Binary(chunk));
    };
    decoder.push(&chunk);
    while let Some(record) = decoder.next_record() {
        pending.push_back(record);
    }
    pending.pop_front().map(XhttpMsg::Binary)
}

/// Wraps one downlink datagram as a length-prefixed record, or `None` when it
/// overflows the `u16` length field (the caller drops it).
fn frame_datagram(payload: &[u8]) -> Option<Bytes> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    match encode_record_into(payload, &mut out) {
        Ok(()) => Some(Bytes::from(out)),
        Err(error) => {
            warn!(?error, len = payload.len(), "dropping oversized xhttp datagram record");
            None
        },
    }
}

/// Wraps the duplex outbound channel as a UDP response sender.
/// XHTTP carries VLESS only and VLESS UDP rides through mux.cool
/// XUDP frames on the same binary channel — so this path is
/// exercised by tests that drive the SS-UDP relay through an
/// XHTTP transport. It just re-tags any byte payload as a binary
/// frame.
struct XhttpUdpResponseSender {
    tx: mpsc::Sender<XhttpMsg>,
    app_protocol: AppProtocol,
    /// Carrier-padding scheme for this path; when enabled each downlink
    /// datagram is framed before it goes on the wire (plain otherwise).
    padding: PaddingScheme,
    /// Per-carrier downstream-throttle monitor; `Some` only on a padded path
    /// with detection on. Fed inbound bytes + send backlog.
    monitor: Option<Arc<crate::server::transport::throughput_monitor::ThroughputMonitor>>,
}

impl ResponseSender for XhttpUdpResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        if let Some(m) = &self.monitor {
            let used = self.tx.max_capacity().saturating_sub(self.tx.capacity());
            m.note_datagram(data.len(), used, self.tx.max_capacity());
        }
        let framed = carrier_padding::frame_downlink_message(self.padding, data);
        Box::pin(async move { self.tx.send(XhttpMsg::Binary(framed)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        // The wire-side carrier is XhttpH2 or XhttpH3 but the trait
        // does not let us thread that distinction through this
        // synthesised sender. Pick `XhttpH2` as the conservative
        // default — it's still distinct from the WS family on
        // the metrics dashboard, and the SS-UDP-over-XHTTP path
        // that would actually exercise this codepath does not
        // exist in this build (XHTTP carries VLESS only).
        Protocol::XhttpH2
    }

    fn app_protocol(&self) -> AppProtocol {
        self.app_protocol
    }
}

#[cfg(test)]
#[path = "tests/duplex.rs"]
mod tests;
