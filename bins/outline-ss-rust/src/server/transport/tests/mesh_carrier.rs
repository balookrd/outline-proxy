use bytes::Bytes;

use super::*;

// Stream I/O (recv chunk / send write / split_io) rides real quinn streams and
// is covered by the phase-8 end-to-end relay test. Here we pin the frame
// mapping — the part where mixing up a variant would silently corrupt the
// relayed stream.

#[test]
fn classify_maps_every_variant() {
    assert!(matches!(
        MeshCarrier::classify(MeshMsg::Binary(Bytes::from_static(b"x"))),
        WsFrame::Binary(_)
    ));
    assert!(matches!(MeshCarrier::classify(MeshMsg::Close), WsFrame::Close));
    assert!(matches!(MeshCarrier::classify(MeshMsg::Ping(Bytes::new())), WsFrame::Ping(_)));
    assert!(matches!(MeshCarrier::classify(MeshMsg::Pong), WsFrame::Pong));
}

#[test]
fn binary_round_trips_through_classify() {
    match MeshCarrier::classify(MeshCarrier::binary_msg(Bytes::from_static(b"payload"))) {
        WsFrame::Binary(b) => assert_eq!(&b[..], b"payload"),
        _ => panic!("binary_msg must classify as Binary"),
    }
}

#[test]
fn lengths_count_only_binary_payload() {
    let m = MeshCarrier::binary_msg(Bytes::from_static(b"hello"));
    assert_eq!(MeshCarrier::binary_len(&m), Some(5));
    assert_eq!(MeshCarrier::msg_len(&m), 5);
    assert_eq!(MeshCarrier::binary_len(&MeshMsg::Close), None);
    assert_eq!(MeshCarrier::msg_len(&MeshMsg::Close), 0);
    assert_eq!(MeshCarrier::msg_len(&MeshMsg::Ping(Bytes::from_static(b"pp"))), 2);
}

#[test]
fn close_variants_and_h3_semantics() {
    assert!(matches!(MeshCarrier::close_msg(), MeshMsg::Close));
    // No client to bounce a retry to on the mesh — a 1013 maps to a plain close.
    assert!(matches!(MeshCarrier::close_try_again_msg(), MeshMsg::Close));
    // QUIC-backed: the relay must not emit server Pings / run pong reaping.
    assert!(MeshCarrier::is_h3());
}
