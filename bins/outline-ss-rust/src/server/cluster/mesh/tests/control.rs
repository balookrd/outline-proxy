use super::{ControlDatagram, encode_throttle_hint, parse_control_datagram};

#[test]
fn throttle_hint_round_trips() {
    let session_id = [7u8; 16];
    let wire = encode_throttle_hint(&session_id);
    assert_eq!(wire.len(), 1 + 16);
    match parse_control_datagram(&wire).unwrap() {
        ControlDatagram::ThrottleHint { session_id: got } => assert_eq!(got, session_id),
    }
}

#[test]
fn distinct_session_ids_round_trip() {
    for n in 0..=255u8 {
        let session_id = [n; 16];
        let wire = encode_throttle_hint(&session_id);
        assert_eq!(
            parse_control_datagram(&wire).unwrap(),
            ControlDatagram::ThrottleHint { session_id }
        );
    }
}

#[test]
fn empty_datagram_is_error() {
    assert!(parse_control_datagram(&[]).is_err());
}

#[test]
fn unknown_kind_is_error() {
    // Kind 0xFF is not a defined control datagram.
    let err = parse_control_datagram(&[0xFF; 17]).unwrap_err();
    assert!(err.to_string().contains("unknown"), "{err}");
}

#[test]
fn wrong_length_is_rejected() {
    // Correct kind byte but truncated / overlong payload.
    let mut short = vec![1u8];
    short.extend_from_slice(&[0u8; 8]);
    assert!(parse_control_datagram(&short).is_err());

    let mut long = vec![1u8];
    long.extend_from_slice(&[0u8; 32]);
    assert!(parse_control_datagram(&long).is_err());
}
