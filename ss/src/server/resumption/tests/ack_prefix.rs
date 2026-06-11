//! Wire-format tests for the Ack-Prefix Protocol v1 control frame.

use super::super::ack_prefix::{FLAGS_NONE, FRAME_LEN_V1, MAGIC, VERSION_V1, build_v1_payload};

#[test]
fn payload_layout_matches_spec() {
    let payload = build_v1_payload(0x0102030405060708);
    assert_eq!(payload.len(), FRAME_LEN_V1);
    assert_eq!(&payload[0..4], &MAGIC);
    assert_eq!(payload[4], VERSION_V1);
    assert_eq!(payload[5], FLAGS_NONE);
    assert_eq!(&payload[6..14], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

#[test]
fn zero_up_acked_serialises_to_zero_bytes() {
    let payload = build_v1_payload(0);
    assert_eq!(&payload[6..14], &[0u8; 8]);
}

#[test]
fn max_up_acked_round_trips() {
    let payload = build_v1_payload(u64::MAX);
    let parsed = u64::from_be_bytes(payload[6..14].try_into().unwrap());
    assert_eq!(parsed, u64::MAX);
}

#[test]
fn magic_is_ascii_orsm() {
    let payload = build_v1_payload(42);
    let magic_str = std::str::from_utf8(&payload[0..4]).unwrap();
    assert_eq!(magic_str, "ORSM");
}
