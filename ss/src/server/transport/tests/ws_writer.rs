//! Tests for the per-session WebSocket writer task.
//!
//! The key H3-safe-keepalive invariant: on a quiet datagram channel the
//! writer must periodically `flush` (to drain a Pong the split reader
//! queued for a client keepalive Ping) but must NOT emit any frame of its
//! own — a server-originated Ping is what tore down the H3 carrier.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::nat::UdpResponseSender;
use crate::server::tests::sample_config;

use crate::server::constants::WS_CONTROL_FLUSH_INTERVAL_SECS;

use super::super::ws_socket::{WsFrame, WsSocket};
use super::super::ws_writer::run_ws_writer;

#[derive(Default)]
struct Counters {
    flush: AtomicUsize,
    send: AtomicUsize,
}

/// A `WsSocket` whose writer half only records how many times the writer
/// task `flush`ed versus `send`. The reader half and frame-coding helpers
/// are unreachable on the writer-only path `run_ws_writer` drives, so they
/// are left `unimplemented!()`.
struct MockWs;

struct MockReader;

struct MockWriter(Arc<Counters>);

enum MockMsg {
    Binary(Bytes),
    Ctrl,
}

impl WsSocket for MockWs {
    type Msg = MockMsg;
    type Reader = MockReader;
    type Writer = MockWriter;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        unimplemented!("run_ws_writer is handed the writer half directly")
    }

    async fn recv(_reader: &mut Self::Reader) -> Result<Option<Self::Msg>> {
        unimplemented!("the writer task never reads")
    }

    async fn send(writer: &mut Self::Writer, _msg: Self::Msg) -> Result<()> {
        writer.0.send.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn finish(_writer: &mut Self::Writer) {}

    async fn flush(writer: &mut Self::Writer) -> Result<()> {
        writer.0.flush.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn is_h3() -> bool {
        false
    }

    fn classify(_msg: Self::Msg) -> WsFrame {
        unimplemented!("the writer task never classifies")
    }

    fn binary_msg(data: Bytes) -> Self::Msg {
        MockMsg::Binary(data)
    }
    fn close_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn close_try_again_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn ping_msg() -> Self::Msg {
        MockMsg::Ctrl
    }
    fn pong_msg(_payload: Bytes) -> Self::Msg {
        MockMsg::Ctrl
    }
    fn binary_len(msg: &Self::Msg) -> Option<usize> {
        match msg {
            MockMsg::Binary(b) => Some(b.len()),
            MockMsg::Ctrl => None,
        }
    }
    fn msg_len(msg: &Self::Msg) -> usize {
        match msg {
            MockMsg::Binary(b) => b.len(),
            MockMsg::Ctrl => 0,
        }
    }
    fn make_udp_response_sender(
        _tx: mpsc::Sender<Self::Msg>,
        _protocol: Protocol,
        _app_protocol: AppProtocol,
    ) -> UdpResponseSender {
        unimplemented!("not exercised by the writer-only path")
    }
}

fn test_metrics() -> Arc<Metrics> {
    Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))))
}

/// On a quiet channel (no ctrl/data messages, mirroring a live-but-idle
/// UDP datagram session) the writer must keep flushing on its timer so a
/// queued reactive Pong reaches the client — and must never `send`, since
/// a server-originated Ping is unsafe on the H3 carrier.
#[tokio::test(start_paused = true)]
async fn writer_flushes_periodically_without_sending_on_quiet_channel() {
    let counters = Arc::new(Counters::default());
    let writer = MockWriter(Arc::clone(&counters));

    // Keep the senders alive so the channels stay open (a live session),
    // but never enqueue anything: the only thing that should run is the
    // flush timer.
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<MockMsg>(8);
    let (data_tx, data_rx) = mpsc::channel::<MockMsg>(8);

    let task = tokio::spawn(run_ws_writer::<MockWs>(
        writer,
        ctrl_rx,
        data_rx,
        test_metrics(),
        Transport::Udp,
        Protocol::Http1,
        AppProtocol::Shadowsocks,
    ));

    // Advance virtual time past three flush intervals.
    tokio::time::sleep(Duration::from_secs(WS_CONTROL_FLUSH_INTERVAL_SECS * 3 + 5)).await;

    assert!(
        counters.flush.load(Ordering::SeqCst) >= 3,
        "writer must flush control frames on its timer while the channel is quiet (got {})",
        counters.flush.load(Ordering::SeqCst),
    );
    assert_eq!(
        counters.send.load(Ordering::SeqCst),
        0,
        "writer must NOT send any frame (no server-originated Ping) on a quiet channel",
    );

    // Closing both channels lets the writer task observe end-of-stream and
    // return cleanly.
    drop(ctrl_tx);
    drop(data_tx);
    let _ = task.await;
}
