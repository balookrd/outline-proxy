use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::types::{SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, TargetAddr};

pub const SOCKS_VERSION: u8 = 0x05;
pub const SOCKS_CMD_CONNECT: u8 = 0x01;
pub const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const SOCKS_STATUS_SUCCESS: u8 = 0x00;
pub const SOCKS_STATUS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const SOCKS_STATUS_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug)]
pub enum SocksRequest {
    Connect(TargetAddr),
    UdpAssociate(TargetAddr),
}

pub struct Socks5UdpPacket<'a> {
    pub fragment: u8,
    pub target: TargetAddr,
    pub payload: &'a [u8],
}

pub const SOCKS5_UDP_FRAGMENT_END: u8 = 0x80;
pub const SOCKS5_UDP_FRAGMENT_MASK: u8 = 0x7f;
pub const SOCKS5_UDP_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledUdpPacket {
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct UdpFragmentReassembler {
    state: Option<UdpFragmentState>,
}

#[derive(Debug)]
struct UdpFragmentState {
    target: TargetAddr,
    fragments: Vec<Vec<u8>>,
    highest_fragment: u8,
    deadline: Instant,
}

pub async fn negotiate(stream: &mut TcpStream) -> Result<SocksRequest> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .context("failed to read method negotiation header")?;

    if header[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version: {}", header[0]);
    }

    let mut methods = vec![0u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .context("failed to read authentication methods")?;

    if !methods.contains(&0x00) {
        stream.write_all(&[SOCKS_VERSION, 0xff]).await.ok();
        bail!("client does not support no-auth method");
    }

    stream
        .write_all(&[SOCKS_VERSION, 0x00])
        .await
        .context("failed to write method selection")?;

    let mut request = [0u8; 4];
    stream
        .read_exact(&mut request)
        .await
        .context("failed to read request header")?;

    if request[0] != SOCKS_VERSION {
        bail!("invalid request version: {}", request[0]);
    }
    if request[2] != 0x00 {
        bail!("reserved byte is not zero");
    }

    let target = read_target_addr(stream, request[3]).await?;
    match request[1] {
        SOCKS_CMD_CONNECT => Ok(SocksRequest::Connect(target)),
        SOCKS_CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate(target)),
        command => {
            send_reply(
                stream,
                SOCKS_STATUS_COMMAND_NOT_SUPPORTED,
                &TargetAddr::IpV4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await
            .ok();
            bail!("unsupported SOCKS command: {command}");
        }
    }
}

pub async fn send_reply(stream: &mut TcpStream, status: u8, bound_addr: &TargetAddr) -> Result<()> {
    let mut reply = vec![SOCKS_VERSION, status, 0x00];
    reply.extend_from_slice(&bound_addr.to_wire_bytes()?);
    stream.write_all(&reply).await?;
    Ok(())
}

pub fn parse_udp_request(packet: &[u8]) -> Result<Socks5UdpPacket<'_>> {
    if packet.len() < 4 {
        bail!("UDP packet is too short");
    }
    if packet[0] != 0 || packet[1] != 0 {
        bail!("invalid UDP reserved bytes");
    }
    let fragment = packet[2];
    let (target, consumed) = TargetAddr::from_wire_bytes(&packet[3..])?;
    let payload_offset = 3 + consumed;
    Ok(Socks5UdpPacket {
        fragment,
        target,
        payload: &packet[payload_offset..],
    })
}

pub fn build_udp_packet(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8, 0u8, 0u8];
    out.extend_from_slice(&target.to_wire_bytes()?);
    out.extend_from_slice(payload);
    Ok(out)
}

impl UdpFragmentReassembler {
    pub fn push_fragment(
        &mut self,
        packet: Socks5UdpPacket<'_>,
    ) -> Result<Option<ReassembledUdpPacket>> {
        if packet.fragment == 0 {
            self.state = None;
            return Ok(Some(ReassembledUdpPacket {
                target: packet.target,
                payload: packet.payload.to_vec(),
            }));
        }

        let fragment_number = packet.fragment & SOCKS5_UDP_FRAGMENT_MASK;
        if fragment_number == 0 {
            bail!("invalid fragmented UDP packet with fragment number 0");
        }
        let is_last = packet.fragment & SOCKS5_UDP_FRAGMENT_END != 0;
        let now = Instant::now();

        if self.state.as_ref().is_some_and(|state| {
            now >= state.deadline
                || packet.target != state.target
                || fragment_number < state.highest_fragment
        }) {
            self.state = None;
        }

        let state = self.state.get_or_insert_with(|| UdpFragmentState {
            target: packet.target.clone(),
            fragments: Vec::new(),
            highest_fragment: 0,
            deadline: now + SOCKS5_UDP_REASSEMBLY_TIMEOUT,
        });

        if packet.target != state.target {
            bail!("fragment target changed within UDP fragment sequence");
        }
        if fragment_number <= state.highest_fragment {
            bail!("out-of-order or duplicate UDP fragment: {fragment_number}");
        }

        state.highest_fragment = fragment_number;
        state.deadline = now + SOCKS5_UDP_REASSEMBLY_TIMEOUT;
        state.fragments.push(packet.payload.to_vec());

        if !is_last {
            return Ok(None);
        }

        let state = self
            .state
            .take()
            .expect("state exists when final fragment arrives");
        let total_len: usize = state.fragments.iter().map(Vec::len).sum();
        let mut payload = Vec::with_capacity(total_len);
        for fragment in state.fragments {
            payload.extend_from_slice(&fragment);
        }

        Ok(Some(ReassembledUdpPacket {
            target: state.target,
            payload,
        }))
    }
}

async fn read_target_addr(stream: &mut TcpStream, atyp: u8) -> Result<TargetAddr> {
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await?;
            let port = read_port(stream).await?;
            Ok(TargetAddr::IpV4(Ipv4Addr::from(raw), port))
        }
        SOCKS_ATYP_IPV6 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await?;
            let port = read_port(stream).await?;
            Ok(TargetAddr::IpV6(Ipv6Addr::from(raw), port))
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            stream.read_exact(&mut raw).await?;
            let port = read_port(stream).await?;
            let host = String::from_utf8(raw).context("domain is not valid UTF-8")?;
            Ok(TargetAddr::Domain(host, port))
        }
        _ => {
            send_reply(
                stream,
                SOCKS_STATUS_ADDRESS_NOT_SUPPORTED,
                &TargetAddr::IpV4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await
            .ok();
            bail!("unsupported address type: {atyp}");
        }
    }
}

async fn read_port(stream: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn socks5_udp_packet_round_trip() {
        let target = TargetAddr::IpV4(Ipv4Addr::new(1, 1, 1, 1), 53);
        let packet = build_udp_packet(&target, b"hello").unwrap();
        let parsed = parse_udp_request(&packet).unwrap();
        assert_eq!(parsed.fragment, 0);
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn udp_fragment_reassembly_round_trip() {
        let mut reassembler = UdpFragmentReassembler::default();
        let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 53);

        let first = vec![0, 0, 1];
        let second = vec![0, 0, SOCKS5_UDP_FRAGMENT_END | 2];

        let mut packet = first;
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"hel");
        let parsed = parse_udp_request(&packet).unwrap();
        assert!(reassembler.push_fragment(parsed).unwrap().is_none());

        let mut packet = second;
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"lo");
        let parsed = parse_udp_request(&packet).unwrap();
        let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();

        assert_eq!(reassembled.target, target);
        assert_eq!(reassembled.payload, b"hello");
    }

    #[test]
    fn udp_fragment_reassembly_resets_on_lower_fragment_number() {
        let mut reassembler = UdpFragmentReassembler::default();
        let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 4, 4), 53);

        let mut packet = vec![0, 0, 2];
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"stale");
        let parsed = parse_udp_request(&packet).unwrap();
        assert!(reassembler.push_fragment(parsed).unwrap().is_none());

        let mut packet = vec![0, 0, SOCKS5_UDP_FRAGMENT_END | 1];
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"fresh");
        let parsed = parse_udp_request(&packet).unwrap();
        let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();

        assert_eq!(reassembled.payload, b"fresh");
    }
}
