//! `TransportStream::is_h3` must follow the XHTTP stream's real carrier:
//! `xhttp_h3` rides QUIC (true), `xhttp_h2`/`xhttp_h1` ride TCP (false).
//!
//! Regression for a spurious H3->H2 carrier downgrade: the WS-level
//! read-idle watchdog was armed on the `xhttp_h3` QUIC carrier because
//! `is_h3` only matched the native `ws_h3` variant. A quiet long-lived
//! session (e.g. an idle push socket) then tripped the 300s reaper and
//! capped the carrier to h2 even though H3 was healthy.

use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::guards::AbortOnDrop;
use crate::ws_stream::TransportStream;
use crate::xhttp::{XhttpStream, XhttpSubmode};

fn dummy_xhttp_stream(carrier_is_h3: bool) -> XhttpStream {
    let (_in_tx, in_rx) = mpsc::channel::<Result<Message, _>>(1);
    let (out_tx, _out_rx) = mpsc::channel::<Message>(1);
    let driver = AbortOnDrop::new(tokio::spawn(async {
        std::future::pending::<()>().await;
    }));
    XhttpStream::from_channels(in_rx, out_tx, driver, XhttpSubmode::PacketUp, carrier_is_h3)
}

#[tokio::test]
async fn xhttp_h3_carrier_reports_is_h3() {
    let stream = dummy_xhttp_stream(true);
    assert!(stream.carrier_is_h3());
    let transport = TransportStream::new_xhttp(stream, None);
    assert!(transport.is_h3(), "xhttp_h3 must be treated as a QUIC carrier");
}

#[tokio::test]
async fn xhttp_h2_carrier_is_not_h3() {
    let stream = dummy_xhttp_stream(false);
    assert!(!stream.carrier_is_h3());
    let transport = TransportStream::new_xhttp(stream, None);
    assert!(!transport.is_h3(), "xhttp_h2/h1 ride TCP and keep the read-idle watchdog");
}
