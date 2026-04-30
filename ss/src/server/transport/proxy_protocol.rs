//! HAProxy PROXY-protocol v1 (text) / v2 (binary) encoder, shared by
//! the L7 HTTP fallback and the L4 SNI fallback. Both always emit the
//! `PROXY` command (no `LOCAL`); `src` is the inbound peer, `dst` is
//! the listener bind address. Mixed-family or unspecified addresses
//! degrade to UNKNOWN (v1) / UNSPEC (v2) so the upstream still gets a
//! well-formed header even when we cannot fill all the slots.
//!
//! v1 is TCP-only by RFC — there is no UDP form on the wire. Callers
//! that need to declare a UDP/QUIC inbound (e.g. an HTTP/3 fallback)
//! must select `ProxyProtocolVersion::V2` and pass `PpTransport::Dgram`;
//! v1 ignores the transport argument and always emits TCP4/TCP6/UNKNOWN.

use std::{io::Write as _, net::SocketAddr};

use crate::config::ProxyProtocolVersion;

/// Transport portion of the v2 `transport_protocol` byte. v1 ignores
/// this — it is TCP-only by spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::server) enum PpTransport {
    /// `STREAM` (low nibble `0x1`). What `[http_fallback]` (TCP
    /// inbound) and `[sni_fallback]` (TCP splice) emit.
    Stream,
    /// `DGRAM` (low nibble `0x2`). For inbound transports that ride
    /// UDP — i.e. the QUIC-backed HTTP/3 fallback. Does not change
    /// what protocol the proxy speaks to the upstream; that part of
    /// the connection is still TCP, the byte just labels the *origin*
    /// of the data we are forwarding.
    Dgram,
}

pub(in crate::server) fn encode_proxy_protocol(
    buf: &mut Vec<u8>,
    version: ProxyProtocolVersion,
    src: SocketAddr,
    dst: SocketAddr,
    transport: PpTransport,
) {
    match version {
        // v1 is TCP-only on the wire; there is no `UDP4` / `UDP6`
        // form. We accept the parameter for a uniform call site but
        // do not vary the output by it. Config-time validation is
        // expected to forbid v1 for UDP-origin inbound listeners.
        ProxyProtocolVersion::V1 => encode_v1(buf, src, dst),
        ProxyProtocolVersion::V2 => encode_v2(buf, src, dst, transport),
    }
}

fn encode_v1(buf: &mut Vec<u8>, src: SocketAddr, dst: SocketAddr) {
    let unspec = src.ip().is_unspecified() || dst.ip().is_unspecified();
    if unspec {
        buf.extend_from_slice(b"PROXY UNKNOWN\r\n");
        return;
    }
    let proto = match (src, dst) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
        (SocketAddr::V6(_), SocketAddr::V6(_)) => "TCP6",
        _ => {
            buf.extend_from_slice(b"PROXY UNKNOWN\r\n");
            return;
        },
    };
    let _ = write!(
        buf,
        "PROXY {proto} {src_ip} {dst_ip} {src_port} {dst_port}\r\n",
        src_ip = src.ip(),
        dst_ip = dst.ip(),
        src_port = src.port(),
        dst_port = dst.port(),
    );
}

fn encode_v2(buf: &mut Vec<u8>, src: SocketAddr, dst: SocketAddr, transport: PpTransport) {
    // 12-byte signature: \r\n\r\n\0\r\nQUIT\n.
    buf.extend_from_slice(&[
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ]);
    // Version + command: 0x21 = v2 + PROXY.
    buf.push(0x21);

    // `transport_protocol` byte = (address_family << 4) | transport.
    // family: 0x1 = AF_INET, 0x2 = AF_INET6, 0x0 = UNSPEC.
    // transport: 0x1 = STREAM, 0x2 = DGRAM.
    let transport_nibble: u8 = match transport {
        PpTransport::Stream => 0x1,
        PpTransport::Dgram => 0x2,
    };
    let unspec = src.ip().is_unspecified() || dst.ip().is_unspecified();
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) if !unspec => {
            buf.push(0x10 | transport_nibble);
            buf.extend_from_slice(&12u16.to_be_bytes());
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        },
        (SocketAddr::V6(s), SocketAddr::V6(d)) if !unspec => {
            buf.push(0x20 | transport_nibble);
            buf.extend_from_slice(&36u16.to_be_bytes());
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        },
        _ => {
            // AF_UNSPEC + UNSPEC — header carries no peer information
            // but is still well-formed.
            buf.push(0x00);
            buf.extend_from_slice(&0u16.to_be_bytes());
        },
    }
}
