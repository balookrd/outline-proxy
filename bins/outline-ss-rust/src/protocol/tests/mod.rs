use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{TargetAddr, parse_target_addr};

#[test]
fn parses_ipv4_target() {
    let bytes = [0x01, 127, 0, 0, 1, 0x1f, 0x90];
    let parsed = parse_target_addr(&bytes).unwrap();
    assert_eq!(
        parsed,
        Some((
            TargetAddr::Socket(SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8080))),
            bytes.len()
        ))
    );
}

#[test]
fn parses_domain_target() {
    let bytes =
        [0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0, 80];
    let parsed = parse_target_addr(&bytes).unwrap();
    assert_eq!(parsed, Some((TargetAddr::Domain("example.com".into(), 80), bytes.len())));
}

#[test]
fn returns_none_for_partial_address() {
    let bytes = [0x03, 0x0b, b'e', b'x'];
    let parsed = parse_target_addr(&bytes).unwrap();
    assert_eq!(parsed, None);
}

#[test]
fn parses_ipv6_target() {
    let bytes = [0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb];
    let parsed = parse_target_addr(&bytes).unwrap();
    assert_eq!(
        parsed,
        Some((
            TargetAddr::Socket(SocketAddr::from((
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                443
            ))),
            bytes.len()
        ))
    );
}

#[test]
fn encodes_ipv6_target() {
    let target = TargetAddr::Socket(SocketAddr::from((
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
        443,
    )));
    let encoded = target.encode().unwrap();

    assert_eq!(
        encoded,
        vec![0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,]
    );
}

proptest::proptest! {
    // parse_target_addr must never panic on arbitrary byte input —
    // it only ever returns Ok(None), Ok(Some(..)), or Err.
    #[test]
    fn parse_target_addr_never_panics(input: Vec<u8>) {
        let _ = parse_target_addr(&input);
    }

    // Round-trip: encode() → parse_target_addr() must recover the original
    // address and report exactly the encoded length as consumed bytes.
    #[test]
    fn encode_parse_roundtrip_ipv4(ip: u32, port: u16) {
        let addr = TargetAddr::Socket(SocketAddr::from((Ipv4Addr::from(ip), port)));
        let bytes = addr.encode().unwrap();
        let (parsed, consumed) = parse_target_addr(&bytes).unwrap().unwrap();
        proptest::prop_assert_eq!(parsed, addr);
        proptest::prop_assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn encode_parse_roundtrip_ipv6(octets: [u8; 16], port: u16) {
        let addr = TargetAddr::Socket(SocketAddr::from((Ipv6Addr::from(octets), port)));
        let bytes = addr.encode().unwrap();
        let (parsed, consumed) = parse_target_addr(&bytes).unwrap().unwrap();
        proptest::prop_assert_eq!(parsed, addr);
        proptest::prop_assert_eq!(consumed, bytes.len());
    }
}
