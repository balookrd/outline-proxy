//! Byte-level coverage for the v2 PROXY-protocol encoder. v1 is text
//! and exercised through the integration tests in
//! `server::tests::fallback`; here we only assert the v2 wire form so
//! the `transport_protocol` byte (low nibble = STREAM | DGRAM) does
//! not silently regress as new callers come online.

use std::net::SocketAddr;

use crate::config::ProxyProtocolVersion;
use crate::server::transport::proxy_protocol::{PpTransport, encode_proxy_protocol};

const V2_SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

fn parse_addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn v2_ipv4_stream_byte_layout() {
    let mut buf = Vec::new();
    encode_proxy_protocol(
        &mut buf,
        ProxyProtocolVersion::V2,
        parse_addr("203.0.113.7:51234"),
        parse_addr("198.51.100.10:443"),
        PpTransport::Stream,
    );

    assert_eq!(&buf[..12], &V2_SIG);
    assert_eq!(buf[12], 0x21, "v2 + PROXY");
    assert_eq!(buf[13], 0x11, "AF_INET + STREAM");
    assert_eq!(u16::from_be_bytes([buf[14], buf[15]]), 12);
    assert_eq!(&buf[16..20], &[203, 0, 113, 7]);
    assert_eq!(&buf[20..24], &[198, 51, 100, 10]);
    assert_eq!(u16::from_be_bytes([buf[24], buf[25]]), 51234);
    assert_eq!(u16::from_be_bytes([buf[26], buf[27]]), 443);
    assert_eq!(buf.len(), 28);
}

#[test]
fn v2_ipv4_dgram_flips_only_the_transport_nibble() {
    // Same addresses as the STREAM case — only the transport nibble
    // should change. This catches encoder drift where someone
    // accidentally rewrites the family nibble too.
    let mut stream = Vec::new();
    encode_proxy_protocol(
        &mut stream,
        ProxyProtocolVersion::V2,
        parse_addr("203.0.113.7:51234"),
        parse_addr("198.51.100.10:443"),
        PpTransport::Stream,
    );
    let mut dgram = Vec::new();
    encode_proxy_protocol(
        &mut dgram,
        ProxyProtocolVersion::V2,
        parse_addr("203.0.113.7:51234"),
        parse_addr("198.51.100.10:443"),
        PpTransport::Dgram,
    );

    assert_eq!(stream.len(), dgram.len());
    assert_eq!(dgram[13], 0x12, "AF_INET + DGRAM");
    // Every other byte is identical.
    let mut expected = stream.clone();
    expected[13] = 0x12;
    assert_eq!(dgram, expected);
}

#[test]
fn v2_ipv6_dgram_byte_layout() {
    let mut buf = Vec::new();
    encode_proxy_protocol(
        &mut buf,
        ProxyProtocolVersion::V2,
        parse_addr("[2001:db8::1]:51234"),
        parse_addr("[2001:db8::abcd]:443"),
        PpTransport::Dgram,
    );

    assert_eq!(&buf[..12], &V2_SIG);
    assert_eq!(buf[12], 0x21);
    assert_eq!(buf[13], 0x22, "AF_INET6 + DGRAM");
    assert_eq!(u16::from_be_bytes([buf[14], buf[15]]), 36);
    assert_eq!(buf.len(), 16 + 36);
}

#[test]
fn v2_unspecified_addresses_keep_unspec_block_regardless_of_transport() {
    // PROXY-protocol cannot describe a half-known peer in v2; the
    // fallback path emits AF_UNSPEC + UNSPEC with a zero-length
    // address block. The transport nibble has nowhere to go in that
    // case, so it must NOT bleed into the family byte.
    for transport in [PpTransport::Stream, PpTransport::Dgram] {
        let mut buf = Vec::new();
        encode_proxy_protocol(
            &mut buf,
            ProxyProtocolVersion::V2,
            parse_addr("0.0.0.0:0"),
            parse_addr("198.51.100.10:443"),
            transport,
        );
        assert_eq!(buf[12], 0x21);
        assert_eq!(buf[13], 0x00, "UNSPEC must not carry transport bits");
        assert_eq!(u16::from_be_bytes([buf[14], buf[15]]), 0);
        assert_eq!(buf.len(), 16);
    }
}

#[test]
fn v1_ignores_transport_argument_and_stays_tcp_only() {
    // RFC has no UDP form for v1. Asking for DGRAM still produces the
    // text TCP4 line — config-time validation is expected to reject
    // v1 + UDP-origin inbound, but the encoder itself should be
    // forgiving rather than panic.
    let mut as_stream = Vec::new();
    encode_proxy_protocol(
        &mut as_stream,
        ProxyProtocolVersion::V1,
        parse_addr("203.0.113.7:51234"),
        parse_addr("198.51.100.10:443"),
        PpTransport::Stream,
    );
    let mut as_dgram = Vec::new();
    encode_proxy_protocol(
        &mut as_dgram,
        ProxyProtocolVersion::V1,
        parse_addr("203.0.113.7:51234"),
        parse_addr("198.51.100.10:443"),
        PpTransport::Dgram,
    );
    assert_eq!(as_stream, as_dgram);
    assert!(as_stream.starts_with(b"PROXY TCP4 "));
}
