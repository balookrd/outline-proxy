//! HAProxy PROXY-protocol v1 (text) / v2 (binary) encoder, shared by
//! the L7 HTTP fallback and the L4 SNI fallback. Both always emit the
//! `PROXY` command (no `LOCAL`); `src` is the inbound peer, `dst` is
//! the listener bind address. Mixed-family or unspecified addresses
//! degrade to UNKNOWN (v1) / UNSPEC (v2) so the upstream still gets a
//! well-formed header even when we cannot fill all the slots.

use std::{io::Write as _, net::SocketAddr};

use crate::config::ProxyProtocolVersion;

pub(in crate::server) fn encode_proxy_protocol(
    buf: &mut Vec<u8>,
    version: ProxyProtocolVersion,
    src: SocketAddr,
    dst: SocketAddr,
) {
    match version {
        ProxyProtocolVersion::V1 => encode_v1(buf, src, dst),
        ProxyProtocolVersion::V2 => encode_v2(buf, src, dst),
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

fn encode_v2(buf: &mut Vec<u8>, src: SocketAddr, dst: SocketAddr) {
    // 12-byte signature: \r\n\r\n\0\r\nQUIT\n.
    buf.extend_from_slice(&[
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ]);
    // Version + command: 0x21 = v2 + PROXY.
    buf.push(0x21);

    let unspec = src.ip().is_unspecified() || dst.ip().is_unspecified();
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) if !unspec => {
            buf.push(0x11); // AF_INET + STREAM (TCP)
            buf.extend_from_slice(&12u16.to_be_bytes());
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        },
        (SocketAddr::V6(s), SocketAddr::V6(d)) if !unspec => {
            buf.push(0x21); // AF_INET6 + STREAM (TCP)
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
