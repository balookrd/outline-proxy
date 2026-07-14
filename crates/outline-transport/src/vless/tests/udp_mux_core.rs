//! VLESS-UDP downlink re-framing.
//!
//! `spawn_vless_udp_mux_session_reader` prepends each session's fixed
//! SOCKS5 target prefix to every downlink datagram so the rest of the
//! stack parses it like the SS-UDP path. The re-frame now reuses one
//! scratch `BytesMut` across datagrams instead of allocating a fresh one
//! per packet; this test pins the wire result — `prefix || payload`,
//! byte-for-byte, across several datagrams of different sizes (so the
//! scratch buffer both grows and reclaims) — so the allocation change
//! cannot silently corrupt the framing.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use parking_lot::Mutex;
use socks5_proto::TargetAddr;
use tokio::sync::{mpsc, watch};

use super::{VlessUdpMuxSession, spawn_vless_udp_mux_session_reader};

/// Session stub that replays a fixed list of downlink payloads, then
/// parks forever so the reader task stays alive (it is aborted on drop).
struct MockSession {
    downlink: Mutex<VecDeque<Bytes>>,
}

impl MockSession {
    fn new(payloads: Vec<Bytes>) -> Self {
        Self { downlink: Mutex::new(payloads.into()) }
    }
}

impl VlessUdpMuxSession for MockSession {
    async fn send_packet(&self, _payload: &[u8]) -> Result<()> {
        Ok(())
    }
    async fn read_packet(&self) -> Result<Bytes> {
        // Take the guard in its own scope so it is not held across the await.
        let next = { self.downlink.lock().pop_front() };
        match next {
            Some(payload) => Ok(payload),
            // Drained: block so the reader neither errors nor spins.
            None => std::future::pending().await,
        }
    }
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn vless_udp_downlink_frames_payload_with_socks5_prefix() {
    let target = TargetAddr::from("8.8.8.8:53".parse::<SocketAddr>().unwrap());
    let prefix = target.to_wire_bytes().unwrap();

    // Sizes chosen to exercise both scratch growth (larger) and reuse
    // (smaller-again), plus an empty payload.
    let payloads = vec![
        Bytes::from_static(b"one"),
        Bytes::from_static(b"a-considerably-larger-downlink-datagram-payload"),
        Bytes::from_static(b"3"),
        Bytes::new(),
        Bytes::from_static(b"last"),
    ];

    let mock = Arc::new(MockSession::new(payloads.clone()));
    let (tx, mut rx) = mpsc::channel::<Result<Bytes>>(16);
    let (_close_tx, close_rx) = watch::channel(false);

    let _reader = spawn_vless_udp_mux_session_reader(mock, target.clone(), tx, close_rx, "test");

    for expected in &payloads {
        let framed = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for downlink frame")
            .expect("downlink channel closed early")
            .expect("session reader surfaced an error");
        assert_eq!(&framed[..prefix.len()], prefix.as_slice(), "SOCKS5 prefix mismatch");
        assert_eq!(&framed[prefix.len()..], expected.as_ref(), "payload mismatch");
    }
}
