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

use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use tokio::sync::mpsc;

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
}

pub(in crate::server) struct XhttpReader {
    session: Arc<XhttpSession>,
}

pub(in crate::server) struct XhttpWriter {
    session: Arc<XhttpSession>,
}

impl WsSocket for XhttpDuplex {
    type Msg = XhttpMsg;
    type Reader = XhttpReader;
    type Writer = XhttpWriter;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        let reader = XhttpReader { session: Arc::clone(&self.session) };
        let writer = XhttpWriter { session: self.session };
        (reader, writer)
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<XhttpMsg>> {
        loop {
            if let Some(chunk) = reader.session.pop_uplink_ready() {
                return Ok(Some(XhttpMsg::Binary(chunk)));
            }
            if reader.session.is_closed() || reader.session.uplink_eof() {
                return Ok(None);
            }
            // Register interest *before* the recheck so a concurrent
            // POST that lands between the pop_uplink_ready and the
            // notify subscription cannot lose the wake-up.
            let notified = reader.session.uplink_notify.notified();
            if let Some(chunk) = reader.session.pop_uplink_ready() {
                return Ok(Some(XhttpMsg::Binary(chunk)));
            }
            if reader.session.is_closed() || reader.session.uplink_eof() {
                return Ok(None);
            }
            notified.await;
        }
    }

    async fn send(writer: &mut Self::Writer, msg: XhttpMsg) -> Result<()> {
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
            // *server* session alive: bump `last_activity` so the
            // registry janitor does not evict an idle-but-live relay
            // out from under us. Without this a UDP datagram channel
            // with a lull longer than `SESSION_IDLE_EVICTION` (DNS
            // between lookups, a quiet QUIC connection) is torn down
            // mid-session and the client sees a spurious `ws closed`.
            // The lower transport (h2/h3 keepalive) keeps the carrier
            // itself live, so the client side does not need a frame.
            XhttpMsg::Noop => {
                writer.session.touch();
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
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(XhttpUdpResponseSender { tx, app_protocol }))
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
}

impl ResponseSender for XhttpUdpResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(XhttpMsg::Binary(data)).await.is_ok() })
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
