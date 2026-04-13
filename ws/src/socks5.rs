use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Socks5AuthConfig, Socks5AuthUserConfig};
use crate::types::{SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, TargetAddr};

pub const SOCKS_VERSION: u8 = 0x05;
pub const SOCKS_CMD_CONNECT: u8 = 0x01;
pub const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const SOCKS_CMD_UDP_IN_TCP: u8 = 0x05;
pub const SOCKS_AUTH_METHOD_NO_AUTH: u8 = 0x00;
pub const SOCKS_AUTH_METHOD_USERNAME_PASSWORD: u8 = 0x02;
pub const SOCKS_AUTH_METHOD_NO_ACCEPTABLE: u8 = 0xff;
pub const SOCKS_STATUS_SUCCESS: u8 = 0x00;
pub const SOCKS_STATUS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const SOCKS_STATUS_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug)]
pub enum SocksRequest {
    Connect(TargetAddr),
    UdpAssociate(TargetAddr),
    UdpInTcp(TargetAddr),
}

pub struct Socks5UdpPacket<'a> {
    pub fragment: u8,
    pub target: TargetAddr,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5UdpTcpPacket {
    pub target: TargetAddr,
    pub payload: Vec<u8>,
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

pub async fn negotiate(
    stream: &mut TcpStream,
    auth: Option<&Socks5AuthConfig>,
) -> Result<SocksRequest> {
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

    match auth {
        Some(auth) => {
            if !methods.contains(&SOCKS_AUTH_METHOD_USERNAME_PASSWORD) {
                stream
                    .write_all(&[SOCKS_VERSION, SOCKS_AUTH_METHOD_NO_ACCEPTABLE])
                    .await
                    .ok();
                bail!("client does not support username/password auth");
            }
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_AUTH_METHOD_USERNAME_PASSWORD])
                .await
                .context("failed to write method selection")?;
            authenticate_username_password(stream, auth).await?;
        },
        None => {
            if !methods.contains(&SOCKS_AUTH_METHOD_NO_AUTH) {
                stream
                    .write_all(&[SOCKS_VERSION, SOCKS_AUTH_METHOD_NO_ACCEPTABLE])
                    .await
                    .ok();
                bail!("client does not support no-auth method");
            }
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_AUTH_METHOD_NO_AUTH])
                .await
                .context("failed to write method selection")?;
        },
    }

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
        SOCKS_CMD_UDP_IN_TCP => Ok(SocksRequest::UdpInTcp(target)),
        command => {
            send_reply(
                stream,
                SOCKS_STATUS_COMMAND_NOT_SUPPORTED,
                &TargetAddr::IpV4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await
            .ok();
            bail!("unsupported SOCKS command: {command}");
        },
    }
}

async fn authenticate_username_password(
    stream: &mut TcpStream,
    auth: &Socks5AuthConfig,
) -> Result<()> {
    let mut version = [0u8; 1];
    stream
        .read_exact(&mut version)
        .await
        .context("failed to read username/password auth version")?;
    if version[0] != 0x01 {
        stream.write_all(&[0x01, 0x01]).await.ok();
        bail!("unsupported username/password auth version: {}", version[0]);
    }

    let username = read_auth_field(stream, "username").await?;
    let password = read_auth_field(stream, "password").await?;
    if !matches_socks5_user(&auth.users, &username, &password) {
        stream.write_all(&[0x01, 0x01]).await.ok();
        bail!("invalid SOCKS5 username/password");
    }

    stream
        .write_all(&[0x01, 0x00])
        .await
        .context("failed to write username/password auth response")?;
    Ok(())
}

async fn read_auth_field(stream: &mut TcpStream, field_name: &str) -> Result<Vec<u8>> {
    let mut len = [0u8; 1];
    stream
        .read_exact(&mut len)
        .await
        .with_context(|| format!("failed to read {field_name} length"))?;
    let mut value = vec![0u8; len[0] as usize];
    stream
        .read_exact(&mut value)
        .await
        .with_context(|| format!("failed to read {field_name}"))?;
    Ok(value)
}

/// Constant-time byte-slice equality to prevent timing side-channel attacks on
/// credential comparison.  Length is compared first (non-constant-time), but an
/// attacker controlling the client already knows the length they submitted, so
/// this leaks no additional information.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn matches_socks5_user(users: &[Socks5AuthUserConfig], username: &[u8], password: &[u8]) -> bool {
    users.iter().any(|user| {
        constant_time_eq(username, user.username.as_bytes())
            && constant_time_eq(password, user.password.as_bytes())
    })
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

pub async fn read_udp_tcp_packet<R>(reader: &mut R) -> Result<Option<Socks5UdpTcpPacket>>
where
    R: AsyncRead + Unpin,
{
    let mut data_len = [0u8; 2];
    let read = reader
        .read(&mut data_len[..1])
        .await
        .context("failed to read UDP-in-TCP data length")?;
    if read == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut data_len[1..])
        .await
        .context("failed to read UDP-in-TCP data length tail")?;
    let data_len = u16::from_be_bytes(data_len) as usize;

    let mut header_len = [0u8; 1];
    reader
        .read_exact(&mut header_len)
        .await
        .context("failed to read UDP-in-TCP header length")?;
    let header_len = header_len[0] as usize;
    let addr_len = header_len
        .checked_sub(3)
        .ok_or_else(|| anyhow::anyhow!("invalid UDP-in-TCP header length: {header_len}"))?;

    let mut addr_buf = vec![0u8; addr_len];
    reader
        .read_exact(&mut addr_buf)
        .await
        .context("failed to read UDP-in-TCP target address")?;
    let (target, consumed) = TargetAddr::from_wire_bytes(&addr_buf)?;
    if consumed != addr_len {
        bail!("UDP-in-TCP header length mismatch");
    }

    let mut payload = vec![0u8; data_len];
    reader
        .read_exact(&mut payload)
        .await
        .context("failed to read UDP-in-TCP payload")?;

    Ok(Some(Socks5UdpTcpPacket { target, payload }))
}

pub async fn write_udp_tcp_packet<W>(
    writer: &mut W,
    target: &TargetAddr,
    payload: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let addr = target.to_wire_bytes()?;
    let header_len = 3 + addr.len();
    let header_len: u8 = header_len
        .try_into()
        .context("UDP-in-TCP header is too large for protocol framing")?;
    let data_len: u16 = payload
        .len()
        .try_into()
        .context("UDP-in-TCP payload exceeds u16 framing limit")?;

    writer
        .write_all(&data_len.to_be_bytes())
        .await
        .context("failed to write UDP-in-TCP data length")?;
    writer
        .write_all(&[header_len])
        .await
        .context("failed to write UDP-in-TCP header length")?;
    writer
        .write_all(&addr)
        .await
        .context("failed to write UDP-in-TCP target address")?;
    writer
        .write_all(payload)
        .await
        .context("failed to write UDP-in-TCP payload")?;
    Ok(())
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

        let state = self.state.take().expect("state exists when final fragment arrives");
        let total_len: usize = state.fragments.iter().map(Vec::len).sum();
        let mut payload = Vec::with_capacity(total_len);
        for fragment in state.fragments {
            payload.extend_from_slice(&fragment);
        }

        Ok(Some(ReassembledUdpPacket { target: state.target, payload }))
    }
}

async fn read_target_addr(stream: &mut TcpStream, atyp: u8) -> Result<TargetAddr> {
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await?;
            let port = read_port(stream).await?;
            Ok(TargetAddr::IpV4(Ipv4Addr::from(raw), port))
        },
        SOCKS_ATYP_IPV6 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await?;
            let port = read_port(stream).await?;
            Ok(TargetAddr::IpV6(Ipv6Addr::from(raw), port))
        },
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            stream.read_exact(&mut raw).await?;
            let port = read_port(stream).await?;
            let host = String::from_utf8(raw).context("domain is not valid UTF-8")?;
            Ok(TargetAddr::Domain(host, port))
        },
        _ => {
            send_reply(
                stream,
                SOCKS_STATUS_ADDRESS_NOT_SUPPORTED,
                &TargetAddr::IpV4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await
            .ok();
            bail!("unsupported address type: {atyp}");
        },
    }
}

async fn read_port(stream: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::net::TcpListener;

    use crate::config::{Socks5AuthConfig, Socks5AuthUserConfig};

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

    #[tokio::test]
    async fn socks5_udp_in_tcp_packet_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let target = TargetAddr::Domain("example.com".to_string(), 53);

        let send = tokio::spawn(async move {
            write_udp_tcp_packet(&mut writer, &target, b"hello").await.unwrap();
        });

        let packet = read_udp_tcp_packet(&mut reader).await.unwrap().unwrap();
        send.await.unwrap();
        assert_eq!(packet.target, TargetAddr::Domain("example.com".to_string(), 53));
        assert_eq!(packet.payload, b"hello");
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

    #[tokio::test]
    async fn negotiate_accepts_no_auth_by_default() {
        let (mut server_stream, mut client) = socks_pair().await;
        let server = tokio::spawn(async move { negotiate(&mut server_stream, None).await });

        client
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_AUTH_METHOD_NO_AUTH]);

        client
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_CMD_CONNECT,
                0x00,
                SOCKS_ATYP_IPV4,
                1,
                2,
                3,
                4,
                0x01,
                0xbb,
            ])
            .await
            .unwrap();

        let request = server.await.unwrap().unwrap();
        match request {
            SocksRequest::Connect(TargetAddr::IpV4(ip, port)) => {
                assert_eq!(ip, Ipv4Addr::new(1, 2, 3, 4));
                assert_eq!(port, 443);
            },
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn negotiate_accepts_udp_in_tcp_request() {
        let (mut server_stream, mut client) = socks_pair().await;
        let server = tokio::spawn(async move { negotiate(&mut server_stream, None).await });

        client
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_AUTH_METHOD_NO_AUTH]);

        client
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_CMD_UDP_IN_TCP,
                0x00,
                SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .unwrap();

        let request = server.await.unwrap().unwrap();
        match request {
            SocksRequest::UdpInTcp(TargetAddr::IpV4(ip, port)) => {
                assert_eq!(ip, Ipv4Addr::UNSPECIFIED);
                assert_eq!(port, 0);
            },
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn negotiate_accepts_pipelined_no_auth_request() {
        let (mut server_stream, mut client) = socks_pair().await;
        let server = tokio::spawn(async move { negotiate(&mut server_stream, None).await });

        client
            .write_all(&[
                SOCKS_VERSION,
                1,
                SOCKS_AUTH_METHOD_NO_AUTH,
                SOCKS_VERSION,
                SOCKS_CMD_CONNECT,
                0x00,
                SOCKS_ATYP_DOMAIN,
                11,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                b'.',
                b'o',
                b'r',
                b'g',
                0,
                53,
            ])
            .await
            .unwrap();

        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_AUTH_METHOD_NO_AUTH]);

        let request = server.await.unwrap().unwrap();
        match request {
            SocksRequest::Connect(TargetAddr::Domain(host, port)) => {
                assert_eq!(host, "example.org");
                assert_eq!(port, 53);
            },
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn negotiate_accepts_pipelined_userpass_udp_in_tcp_request() {
        let (mut server_stream, mut client) = socks_pair().await;
        let auth = Socks5AuthConfig {
            users: vec![Socks5AuthUserConfig {
                username: "alice".to_string(),
                password: "secret".to_string(),
            }],
        };
        let server = tokio::spawn(async move { negotiate(&mut server_stream, Some(&auth)).await });

        client
            .write_all(&[
                SOCKS_VERSION,
                1,
                SOCKS_AUTH_METHOD_USERNAME_PASSWORD,
                0x01,
                5,
                b'a',
                b'l',
                b'i',
                b'c',
                b'e',
                6,
                b's',
                b'e',
                b'c',
                b'r',
                b'e',
                b't',
                SOCKS_VERSION,
                SOCKS_CMD_UDP_IN_TCP,
                0x00,
                SOCKS_ATYP_IPV4,
                0,
                0,
                0,
                0,
                0,
                0,
            ])
            .await
            .unwrap();

        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_AUTH_METHOD_USERNAME_PASSWORD]);

        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x00]);

        let request = server.await.unwrap().unwrap();
        match request {
            SocksRequest::UdpInTcp(TargetAddr::IpV4(ip, port)) => {
                assert_eq!(ip, Ipv4Addr::UNSPECIFIED);
                assert_eq!(port, 0);
            },
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn negotiate_accepts_username_password_auth() {
        let (mut server_stream, mut client) = socks_pair().await;
        let auth = Socks5AuthConfig {
            users: vec![
                Socks5AuthUserConfig {
                    username: "alice".to_string(),
                    password: "secret".to_string(),
                },
                Socks5AuthUserConfig {
                    username: "bob".to_string(),
                    password: "hunter2".to_string(),
                },
            ],
        };
        let server = tokio::spawn(async move { negotiate(&mut server_stream, Some(&auth)).await });

        client
            .write_all(&[
                SOCKS_VERSION,
                2,
                SOCKS_AUTH_METHOD_NO_AUTH,
                SOCKS_AUTH_METHOD_USERNAME_PASSWORD,
            ])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_AUTH_METHOD_USERNAME_PASSWORD]);

        client
            .write_all(&[0x01, 3, b'b', b'o', b'b', 7, b'h', b'u', b'n', b't', b'e', b'r', b'2'])
            .await
            .unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x00]);

        client
            .write_all(&[
                SOCKS_VERSION,
                SOCKS_CMD_CONNECT,
                0x00,
                SOCKS_ATYP_DOMAIN,
                11,
                b'e',
                b'x',
                b'a',
                b'm',
                b'p',
                b'l',
                b'e',
                b'.',
                b'c',
                b'o',
                b'm',
                0,
                80,
            ])
            .await
            .unwrap();

        let request = server.await.unwrap().unwrap();
        match request {
            SocksRequest::Connect(TargetAddr::Domain(host, port)) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 80);
            },
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[tokio::test]
    async fn negotiate_rejects_invalid_username_password() {
        let (mut server_stream, mut client) = socks_pair().await;
        let auth = Socks5AuthConfig {
            users: vec![Socks5AuthUserConfig {
                username: "alice".to_string(),
                password: "secret".to_string(),
            }],
        };
        let server = tokio::spawn(async move { negotiate(&mut server_stream, Some(&auth)).await });

        client
            .write_all(&[SOCKS_VERSION, 1, SOCKS_AUTH_METHOD_USERNAME_PASSWORD])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_AUTH_METHOD_USERNAME_PASSWORD]);

        client
            .write_all(&[0x01, 5, b'a', b'l', b'i', b'c', b'e', 5, b'w', b'r', b'o', b'n', b'g'])
            .await
            .unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x01]);

        let err = server.await.unwrap().unwrap_err();
        assert!(format!("{err:#}").contains("invalid SOCKS5 username/password"));
    }

    async fn socks_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (server, client)
    }
}
