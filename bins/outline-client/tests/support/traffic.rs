#![allow(dead_code)]
//! Traffic drivers layered on the existing blocking SOCKS5 helpers in
//! `proxy_test_utils`. Used as a submodule of `failover_harness`, so it reaches
//! the SOCKS5 client through `super::proxy_test_utils`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use super::proxy_test_utils::{socks5_connect, socks5_udp_associate};

type BoxError = Box<dyn std::error::Error>;

/// One fresh SOCKS5 CONNECT to the echo upstream: write `payload`, read it
/// back, assert byte-for-byte equality. A clean pass proves the whole tunnel
/// (client → active wire/uplink → server → echo) is intact end-to-end.
pub fn socks5_echo_roundtrip(
    proxy_port: u16,
    echo: SocketAddr,
    payload: &[u8],
) -> Result<(), BoxError> {
    let host = echo.ip().to_string();
    let mut stream = socks5_connect(proxy_port, &host, echo.port())?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(payload)?;
    let mut buf = vec![0u8; payload.len()];
    stream.read_exact(&mut buf)?;
    if buf != payload {
        return Err("echo payload mismatch through tunnel".into());
    }
    Ok(())
}

/// Same as [`socks5_echo_roundtrip`] but ignores the result — handy for warming
/// a wire or forcing a dial attempt where only the side effect matters.
pub fn socks5_echo_attempt(proxy_port: u16, echo: SocketAddr) -> Result<(), BoxError> {
    socks5_echo_roundtrip(proxy_port, echo, b"warm")
}

/// A held-open SOCKS5 CONNECT for mid-session tests: send some bytes, force a
/// carrier break externally, then send more and confirm nothing was lost.
pub struct ContinuousEcho {
    stream: TcpStream,
    sent: usize,
}

impl ContinuousEcho {
    pub fn connect(proxy_port: u16, echo: SocketAddr) -> Result<Self, BoxError> {
        let host = echo.ip().to_string();
        let stream = socks5_connect(proxy_port, &host, echo.port())?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(Duration::from_secs(15)))?;
        Ok(Self { stream, sent: 0 })
    }

    /// Write a chunk and read its echo back, asserting equality. Used both
    /// before and after a `cut()` to prove the resumed session is lossless.
    pub fn echo_chunk(&mut self, data: &[u8]) -> Result<(), BoxError> {
        self.stream.write_all(data)?;
        self.sent += data.len();
        let mut buf = vec![0u8; data.len()];
        self.stream.read_exact(&mut buf)?;
        if buf != data {
            return Err("continuous echo mismatch".into());
        }
        Ok(())
    }

    pub fn total_sent(&self) -> usize {
        self.sent
    }
}

/// Send a single UDP datagram to `udp_target` through a SOCKS5 UDP ASSOCIATE
/// relay and read the echoed bytes back. Returns the echoed payload.
pub fn socks5_udp_echo(
    proxy_port: u16,
    udp_target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, BoxError> {
    use super::proxy_test_utils::{build_udp_packet, parse_udp_packet};

    let (_control, relay_addr) = socks5_udp_associate(proxy_port)?;
    let client = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    client.set_write_timeout(Some(Duration::from_secs(10)))?;

    let host = udp_target.ip().to_string();
    let packet = build_udp_packet(&host, udp_target.port(), payload)?;
    client.send_to(&packet, relay_addr)?;

    let mut buf = [0u8; 4096];
    let (n, _) = client.recv_from(&mut buf)?;
    let parsed = parse_udp_packet(&buf[..n])?;
    Ok(parsed.payload)
}
