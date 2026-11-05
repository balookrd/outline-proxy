//! Tests for the mux TCP sub-connection reader: downlink sizing and the held
//! VLESS response header.

use bytes::BytesMut;
use outline_wire::padding::PaddingScheme;

use super::*;
use crate::server::transport::carrier_padding::{H2_DATA_PAYLOAD_MAX, H2_WS_HEADER_LEN};

/// Off h2 the reader keeps its whole relay buffer as the read limit.
#[test]
fn read_limit_is_the_buffer_off_h2() {
    for protocol in [Protocol::Http1, Protocol::XhttpH1, Protocol::Http3, Protocol::XhttpH3] {
        for padding in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            assert_eq!(read_limit(16 * 1024, protocol, padding, 0), 16 * 1024, "{protocol:?}");
        }
    }
}

/// On h2 a full mux data frame at the limit, padded at the scheme's largest
/// pad and behind its WS header, is exactly one h2 DATA frame of one record.
#[test]
fn a_full_data_frame_at_the_h2_limit_fits_one_data_frame() {
    for protocol in [Protocol::Http2, Protocol::XhttpH2] {
        for padding in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            let limit = read_limit(16 * 1024, protocol, padding, 0);
            assert!(limit < 16 * 1024, "{protocol:?} {padding:?}");
            let mut frame = BytesMut::new();
            encode_frame(
                &mut frame,
                0x1234,
                SessionStatus::Keep,
                OPTION_DATA,
                None,
                None,
                Some(&vec![0u8; limit]),
            )
            .expect("a capped data frame encodes");
            assert_eq!(frame.len(), limit + MUX_DATA_FRAME_OVERHEAD);
            let pad = if padding.is_enabled() {
                4 + usize::from(padding.max_pad())
            } else {
                0
            };
            assert_eq!(
                frame.len() + pad + H2_WS_HEADER_LEN,
                H2_DATA_PAYLOAD_MAX,
                "{protocol:?} {padding:?}"
            );
        }
    }
}

/// While the session's response header is still held, the read leaves room for
/// it on h2, so the header-carrying first frame still fits the budget.
#[test]
fn read_limit_leaves_room_for_the_held_header() {
    for protocol in [Protocol::Http2, Protocol::XhttpH2] {
        for padding in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            assert_eq!(
                read_limit(16 * 1024, protocol, padding, 2),
                read_limit(16 * 1024, protocol, padding, 0) - 2,
                "{protocol:?} {padding:?}"
            );
        }
    }
    assert_eq!(read_limit(16 * 1024, Protocol::Http1, PaddingScheme::disabled(), 2), 16 * 1024);
}

/// The first downlink frame of a sub-connection carries the held header in
/// front of it; the `End` frame that follows does not.
#[tokio::test]
async fn first_downlink_frame_carries_the_held_header() {
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Notify, mpsc};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let (reader, _writer) = client.unwrap().into_split();
    let (mut upstream, _) = accepted.unwrap();
    upstream.write_all(b"hello").await.unwrap();
    upstream.shutdown().await.unwrap();
    drop(upstream);

    let header = Arc::new(HeldResponseHeader::new(bytes::Bytes::from_static(&[0x00, 0x00])));
    let (tx, mut rx) = mpsc::channel::<bytes::Bytes>(8);
    let harvest = run_tcp_reader(
        7,
        reader,
        tx,
        |b| b,
        None,
        Protocol::Http2,
        PaddingScheme::disabled(),
        Some(Arc::clone(&header)),
        Arc::new(Notify::new()),
    )
    .await;
    assert!(matches!(harvest, MuxReaderHarvest::Closed));

    let mut keep = BytesMut::new();
    encode_frame(&mut keep, 7, SessionStatus::Keep, OPTION_DATA, None, None, Some(b"hello"))
        .unwrap();
    let mut end = BytesMut::new();
    encode_frame(&mut end, 7, SessionStatus::End, 0, None, None, None).unwrap();
    let mut first = vec![0x00, 0x00];
    first.extend_from_slice(&keep);
    assert_eq!(rx.recv().await.unwrap(), first);
    assert_eq!(rx.recv().await.unwrap(), end.freeze());
    assert!(rx.recv().await.is_none());
    assert_eq!(header.pending_len(), 0);
}
