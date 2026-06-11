use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

#[test]
fn parses_ipv4_target() {
    let bytes = [0x01, 127, 0, 0, 1, 0x1f, 0x90];
    let parsed = parse_target_addr(&bytes).unwrap();
    assert_eq!(parsed, Some((TargetAddr::IpV4(Ipv4Addr::new(127, 0, 0, 1), 8080), bytes.len())));
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
            TargetAddr::IpV6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 443),
            bytes.len()
        ))
    );
}

#[test]
fn encodes_ipv6_target() {
    let target = TargetAddr::IpV6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 443);
    let encoded = target.to_wire_bytes().unwrap();

    assert_eq!(
        encoded,
        vec![0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,]
    );
}

#[test]
fn strict_decode_rejects_empty_buffer() {
    assert_eq!(TargetAddr::from_wire_bytes(&[]), Err(TargetAddrError::EmptyBuffer));
}

#[test]
fn strict_decode_rejects_truncated_input() {
    let bytes = [0x03, 0x0b, b'e', b'x'];
    assert_eq!(
        TargetAddr::from_wire_bytes(&bytes),
        Err(TargetAddrError::ShortAddress { kind: "domain" })
    );
    assert_eq!(
        TargetAddr::from_wire_bytes(&[0x01, 127, 0]),
        Err(TargetAddrError::ShortAddress { kind: "IPv4" })
    );
}

#[test]
fn rejects_unknown_atyp() {
    assert_eq!(
        TargetAddr::from_wire_bytes(&[0x05, 0, 0]),
        Err(TargetAddrError::UnsupportedAddressType(0x05))
    );
    assert_eq!(
        parse_target_addr(&[0x05, 0, 0]),
        Err(TargetAddrError::UnsupportedAddressType(0x05))
    );
}

#[test]
fn rejects_oversized_domain_on_encode() {
    let target = TargetAddr::Domain("a".repeat(256), 80);
    assert_eq!(target.to_wire_bytes(), Err(TargetAddrError::DomainTooLong));
}

#[test]
fn socket_addr_helpers() {
    let v4 = TargetAddr::IpV4(Ipv4Addr::new(10, 0, 0, 1), 8080);
    assert_eq!(v4.socket_addr(), Some(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 8080))));
    assert_eq!(v4.port(), 8080);

    let domain = TargetAddr::Domain("example.com".into(), 80);
    assert_eq!(domain.socket_addr(), None);
    assert_eq!(domain.port(), 80);

    let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
    assert_eq!(TargetAddr::from(addr).socket_addr(), Some(addr));
    assert_eq!(socket_addr_to_target(addr), TargetAddr::from(addr));
}

#[test]
fn display_formats() {
    assert_eq!(TargetAddr::IpV4(Ipv4Addr::new(1, 2, 3, 4), 80).to_string(), "1.2.3.4:80");
    assert_eq!(TargetAddr::IpV6(Ipv6Addr::LOCALHOST, 443).to_string(), "[::1]:443");
    assert_eq!(TargetAddr::Domain("example.com".into(), 80).to_string(), "example.com:80");
}

proptest::proptest! {
    // parse_target_addr must never panic on arbitrary byte input —
    // it only ever returns Ok(None), Ok(Some(..)), or Err.
    #[test]
    fn parse_target_addr_never_panics(input: Vec<u8>) {
        let _ = parse_target_addr(&input);
        let _ = TargetAddr::from_wire_bytes(&input);
    }

    // Round-trip: to_wire_bytes() → parse must recover the original
    // address and report exactly the encoded length as consumed bytes.
    #[test]
    fn encode_parse_roundtrip_ipv4(ip: u32, port: u16) {
        let addr = TargetAddr::IpV4(Ipv4Addr::from(ip), port);
        let bytes = addr.to_wire_bytes().unwrap();
        let (parsed, consumed) = parse_target_addr(&bytes).unwrap().unwrap();
        proptest::prop_assert_eq!(&parsed, &addr);
        proptest::prop_assert_eq!(consumed, bytes.len());
        let (parsed, consumed) = TargetAddr::from_wire_bytes(&bytes).unwrap();
        proptest::prop_assert_eq!(parsed, addr);
        proptest::prop_assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn encode_parse_roundtrip_ipv6(octets: [u8; 16], port: u16) {
        let addr = TargetAddr::IpV6(Ipv6Addr::from(octets), port);
        let bytes = addr.to_wire_bytes().unwrap();
        let (parsed, consumed) = parse_target_addr(&bytes).unwrap().unwrap();
        proptest::prop_assert_eq!(&parsed, &addr);
        proptest::prop_assert_eq!(consumed, bytes.len());
        let (parsed, consumed) = TargetAddr::from_wire_bytes(&bytes).unwrap();
        proptest::prop_assert_eq!(parsed, addr);
        proptest::prop_assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn encode_parse_roundtrip_domain(host in "[a-z0-9.-]{1,255}", port: u16) {
        let addr = TargetAddr::Domain(host, port);
        let bytes = addr.to_wire_bytes().unwrap();
        let (parsed, consumed) = TargetAddr::from_wire_bytes(&bytes).unwrap();
        proptest::prop_assert_eq!(parsed, addr);
        proptest::prop_assert_eq!(consumed, bytes.len());
    }
}
