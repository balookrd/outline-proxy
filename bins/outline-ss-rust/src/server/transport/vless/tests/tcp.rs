//! Tests for the VLESS TCP upstream→client relay: the response header must
//! travel inside the first data message (or alone before close), never as its
//! own tiny record.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use outline_wire::padding::PaddingScheme;

use super::*;
use crate::metrics::Metrics;
use crate::server::resumption::downlink_ring::{DownlinkRing, ReplayOutcome};
use crate::server::tests::sample_config;

#[derive(Debug, PartialEq)]
enum Msg {
    Binary(Bytes),
    Close,
}

struct ScriptedUpstream {
    chunks: VecDeque<Vec<u8>>,
}

impl UpstreamRead for ScriptedUpstream {
    async fn readable(&self) -> std::io::Result<()> {
        Ok(())
    }

    fn try_read_buf<B: bytes::BufMut>(&mut self, buf: &mut B) -> std::io::Result<usize> {
        match self.chunks.pop_front() {
            Some(chunk) => {
                buf.put_slice(&chunk);
                Ok(chunk.len())
            },
            None => Ok(0),
        }
    }
}

const HEADER: [u8; 2] = [vless::VERSION, 0x00];

async fn run_relay(
    chunks: Vec<Vec<u8>>,
    header: Option<Bytes>,
    ring: Option<Arc<Mutex<DownlinkRing>>>,
) -> Vec<Msg> {
    let (tx, mut rx) = mpsc::channel::<Msg>(16);
    let metrics = Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))));
    let outcome = relay_vless_upstream_to_client(
        ScriptedUpstream { chunks: chunks.into() },
        |_| HarvestedUpstream::Mesh,
        tx,
        Msg::Binary,
        || Msg::Close,
        metrics,
        Protocol::Http1,
        Arc::from("beerloga"),
        None,
        ring,
        PaddingScheme::disabled(),
        None,
        header,
    )
    .await
    .expect("relay completes");
    assert!(matches!(outcome, VlessRelayOutcome::Closed));
    let mut out = Vec::new();
    while let Some(m) = rx.recv().await {
        out.push(m);
    }
    out
}

#[tokio::test]
async fn header_is_prepended_to_the_first_data_message() {
    let msgs = run_relay(vec![b"hello".to_vec()], Some(Bytes::from_static(&HEADER)), None).await;
    let mut expected = HEADER.to_vec();
    expected.extend_from_slice(b"hello");
    assert_eq!(msgs, vec![Msg::Binary(Bytes::from(expected)), Msg::Close]);
}

#[tokio::test]
async fn header_goes_alone_before_close_when_upstream_sends_nothing() {
    let msgs = run_relay(vec![], Some(Bytes::from_static(&HEADER)), None).await;
    assert_eq!(msgs, vec![Msg::Binary(Bytes::from_static(&HEADER)), Msg::Close]);
}

#[tokio::test]
async fn header_is_not_recorded_in_the_downlink_ring() {
    let ring = Arc::new(Mutex::new(DownlinkRing::new(1024)));
    let _ = run_relay(
        vec![b"hello".to_vec()],
        Some(Bytes::from_static(&HEADER)),
        Some(Arc::clone(&ring)),
    )
    .await;
    let ReplayOutcome::Available(bytes) = ring.lock().replay_from(0) else {
        panic!("ring must hold the payload");
    };
    assert_eq!(bytes, b"hello", "header bytes must not be replayable as data");
}

#[tokio::test]
async fn no_header_leaves_messages_unchanged() {
    let msgs = run_relay(vec![b"hello".to_vec()], None, None).await;
    assert_eq!(msgs, vec![Msg::Binary(Bytes::from_static(b"hello")), Msg::Close]);
}
