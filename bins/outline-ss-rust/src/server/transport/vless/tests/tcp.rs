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
        // Like a socket (and the mesh upstream), hand over only what `buf`
        // has room for and keep the rest of the chunk for the next read.
        match self.chunks.pop_front() {
            Some(mut chunk) => {
                let n = chunk.len().min(buf.remaining_mut());
                let rest = chunk.split_off(n);
                buf.put_slice(&chunk);
                if !rest.is_empty() {
                    self.chunks.push_front(rest);
                }
                Ok(n)
            },
            None => Ok(0), // EOF
        }
    }
}

const HEADER: [u8; 2] = [vless::VERSION, 0x00];

async fn run_relay(
    chunks: Vec<Vec<u8>>,
    header: Option<Bytes>,
    ring: Option<Arc<Mutex<DownlinkRing>>>,
) -> Vec<Msg> {
    run_relay_on(Protocol::Http1, PaddingScheme::disabled(), chunks, header, ring).await
}

async fn run_relay_on(
    protocol: Protocol,
    padding: PaddingScheme,
    chunks: Vec<Vec<u8>>,
    header: Option<Bytes>,
    ring: Option<Arc<Mutex<DownlinkRing>>>,
) -> Vec<Msg> {
    // Roomy enough for a shaped, capped 64 KiB download: the receiver is only
    // drained after the relay returns.
    let (tx, mut rx) = mpsc::channel::<Msg>(1024);
    let metrics = Metrics::new(&sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000))));
    let outcome = relay_vless_upstream_to_client(
        ScriptedUpstream { chunks: chunks.into() },
        |_| HarvestedUpstream::Mesh,
        tx,
        Msg::Binary,
        || Msg::Close,
        metrics,
        protocol,
        Arc::from("beerloga"),
        None,
        ring,
        padding,
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

/// On an h2 carrier every downlink message, the header-carrying first one
/// included, fits one h2 DATA frame of one TLS record together with its WS
/// header, and the messages still decode back to header + data.
#[tokio::test]
async fn h2_messages_fit_one_data_frame_and_round_trip() {
    use crate::server::transport::carrier_padding::{H2_DATA_PAYLOAD_MAX, H2_WS_HEADER_LEN};
    use outline_wire::padding::PaddingDecoder;

    let data: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
    for protocol in [Protocol::Http2, Protocol::XhttpH2] {
        for padding in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            // Two reads: one 64 KiB burst (more than the drain target) and a
            // second one past the early-shaping window.
            let msgs = run_relay_on(
                protocol,
                padding,
                vec![data.clone(), data.clone()],
                Some(Bytes::from_static(&HEADER)),
                None,
            )
            .await;
            assert_eq!(msgs.last(), Some(&Msg::Close));
            let mut decoder = PaddingDecoder::new();
            let mut stream = Vec::new();
            for m in &msgs[..msgs.len() - 1] {
                let Msg::Binary(b) = m else { panic!("only the last message closes") };
                assert!(
                    b.len() + H2_WS_HEADER_LEN <= H2_DATA_PAYLOAD_MAX,
                    "{protocol:?} {padding:?}: message of {} B",
                    b.len()
                );
                if padding.is_enabled() {
                    decoder.push(b, &mut stream);
                } else {
                    stream.extend_from_slice(b);
                }
            }
            let mut expected = HEADER.to_vec();
            expected.extend_from_slice(&data);
            expected.extend_from_slice(&data);
            assert_eq!(stream, expected, "{protocol:?} {padding:?}");
        }
    }
}

/// Off h2 the read still goes out as one message (no shaping on h3).
#[tokio::test]
async fn h3_keeps_one_message_per_read() {
    let data = vec![0x33; 40_000];
    let msgs =
        run_relay_on(Protocol::Http3, PaddingScheme::disabled(), vec![data.clone()], None, None)
            .await;
    assert_eq!(msgs, vec![Msg::Binary(Bytes::from(data)), Msg::Close]);
}

/// A bulk download on h2 (far more than one message available at once): every
/// message fits the budget and none but the last is small. A small remainder
/// message ahead of a full one is what h2 coalesces into one write that spills
/// a full TLS record plus a small one.
#[tokio::test]
async fn h2_bulk_download_has_no_small_middle_messages() {
    use crate::server::transport::carrier_padding::{H2_DATA_PAYLOAD_MAX, H2_WS_HEADER_LEN};
    use outline_wire::padding::PaddingDecoder;

    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    for protocol in [Protocol::Http2, Protocol::XhttpH2] {
        for padding in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            let msgs = run_relay_on(
                protocol,
                padding,
                vec![data.clone()],
                Some(Bytes::from_static(&HEADER)),
                None,
            )
            .await;
            let (close, binaries) = msgs.split_last().expect("messages were sent");
            assert_eq!(close, &Msg::Close);
            let mut decoder = PaddingDecoder::new();
            let mut stream = Vec::new();
            for (i, m) in binaries.iter().enumerate() {
                let Msg::Binary(b) = m else { panic!("only the last message closes") };
                assert!(
                    b.len() + H2_WS_HEADER_LEN <= H2_DATA_PAYLOAD_MAX,
                    "{protocol:?} {padding:?}: message {i} of {} B",
                    b.len()
                );
                if i + 1 < binaries.len() {
                    assert!(
                        b.len() >= 256,
                        "{protocol:?} {padding:?}: message {i} of {} B",
                        b.len()
                    );
                }
                if padding.is_enabled() {
                    decoder.push(b, &mut stream);
                } else {
                    stream.extend_from_slice(b);
                }
            }
            let mut expected = HEADER.to_vec();
            expected.extend_from_slice(&data);
            assert_eq!(stream, expected, "{protocol:?} {padding:?}");
        }
    }
}
