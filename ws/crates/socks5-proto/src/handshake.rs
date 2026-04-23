use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Socks5AuthConfig, Socks5AuthUserConfig};
use crate::constants::*;
use crate::error::{Result, Socks5Error};
use crate::target::{SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, TargetAddr};

#[derive(Debug)]
pub enum SocksRequest {
    Connect(TargetAddr),
    UdpAssociate(TargetAddr),
    UdpInTcp(TargetAddr),
}

pub async fn negotiate(
    stream: &mut TcpStream,
    auth: Option<&Socks5AuthConfig>,
) -> Result<SocksRequest> {
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(Socks5Error::io("reading method negotiation header"))?;

    if header[0] != SOCKS_VERSION {
        return Err(Socks5Error::UnsupportedVersion(header[0]));
    }

    let mut methods = vec![0u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(Socks5Error::io("reading authentication methods"))?;

    match auth {
        Some(auth) => {
            if !methods.contains(&SOCKS_METHOD_USERNAME_PASSWORD) {
                stream
                    .write_all(&[SOCKS_VERSION, SOCKS_METHOD_NO_ACCEPTABLE])
                    .await
                    .ok();
                return Err(Socks5Error::UnsupportedAuthMethod);
            }
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_METHOD_USERNAME_PASSWORD])
                .await
                .map_err(Socks5Error::io("writing method selection"))?;
            authenticate_username_password(stream, auth).await?;
        },
        None => {
            if !methods.contains(&SOCKS_METHOD_NO_AUTH) {
                stream
                    .write_all(&[SOCKS_VERSION, SOCKS_METHOD_NO_ACCEPTABLE])
                    .await
                    .ok();
                return Err(Socks5Error::UnsupportedAuthMethod);
            }
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_METHOD_NO_AUTH])
                .await
                .map_err(Socks5Error::io("writing method selection"))?;
        },
    }

    let mut request = [0u8; 4];
    stream
        .read_exact(&mut request)
        .await
        .map_err(Socks5Error::io("reading request header"))?;

    if request[0] != SOCKS_VERSION {
        return Err(Socks5Error::InvalidRequestVersion(request[0]));
    }
    if request[2] != 0x00 {
        return Err(Socks5Error::ReservedByteNonZero);
    }

    let target = read_target_addr(stream, request[3]).await?;
    match request[1] {
        SOCKS_CMD_CONNECT => Ok(SocksRequest::Connect(target)),
        SOCKS_CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate(target)),
        SOCKS_CMD_UDP_IN_TCP => Ok(SocksRequest::UdpInTcp(target)),
        command => {
            send_reply(
                stream,
                SOCKS_REP_COMMAND_NOT_SUPPORTED,
                &TargetAddr::IpV4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await
            .ok();
            Err(Socks5Error::UnsupportedCommand(command))
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
        .map_err(Socks5Error::io("reading username/password auth version"))?;
    if version[0] != 0x01 {
        stream.write_all(&[0x01, 0x01]).await.ok();
        return Err(Socks5Error::UnsupportedAuthVersion(version[0]));
    }

    let username = read_auth_field(stream, "username").await?;
    let password = read_auth_field(stream, "password").await?;
    if !matches_socks5_user(&auth.users, &username, &password) {
        stream.write_all(&[0x01, 0x01]).await.ok();
        return Err(Socks5Error::InvalidCredentials);
    }

    stream
        .write_all(&[0x01, 0x00])
        .await
        .map_err(Socks5Error::io("writing username/password auth response"))?;
    Ok(())
}

async fn read_auth_field(stream: &mut TcpStream, field_name: &'static str) -> Result<Vec<u8>> {
    let mut len = [0u8; 1];
    stream
        .read_exact(&mut len)
        .await
        .map_err(Socks5Error::io(match field_name {
            "username" => "reading username length",
            _ => "reading password length",
        }))?;
    let mut value = vec![0u8; len[0] as usize];
    stream
        .read_exact(&mut value)
        .await
        .map_err(Socks5Error::io(match field_name {
            "username" => "reading username",
            _ => "reading password",
        }))?;
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
    stream
        .write_all(&reply)
        .await
        .map_err(Socks5Error::io("writing SOCKS reply"))?;
    Ok(())
}

async fn read_target_addr(stream: &mut TcpStream, atyp: u8) -> Result<TargetAddr> {
    match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut raw = [0u8; 4];
            stream
                .read_exact(&mut raw)
                .await
                .map_err(Socks5Error::io("reading IPv4 target address"))?;
            let port = read_port(stream).await?;
            Ok(TargetAddr::IpV4(Ipv4Addr::from(raw), port))
        },
        SOCKS_ATYP_IPV6 => {
            let mut raw = [0u8; 16];
            stream
                .read_exact(&mut raw)
                .await
                .map_err(Socks5Error::io("reading IPv6 target address"))?;
            let port = read_port(stream).await?;
            Ok(TargetAddr::IpV6(Ipv6Addr::from(raw), port))
        },
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(Socks5Error::io("reading domain length"))?;
            let mut raw = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut raw)
                .await
                .map_err(Socks5Error::io("reading domain bytes"))?;
            let port = read_port(stream).await?;
            let host = String::from_utf8(raw).map_err(|_| Socks5Error::DomainNotUtf8)?;
            Ok(TargetAddr::Domain(host, port))
        },
        _ => {
            send_reply(
                stream,
                SOCKS_REP_ADDRESS_NOT_SUPPORTED,
                &TargetAddr::IpV4(Ipv4Addr::UNSPECIFIED, 0),
            )
            .await
            .ok();
            Err(Socks5Error::UnsupportedAddressType(atyp))
        },
    }
}

async fn read_port(stream: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(Socks5Error::io("reading target port"))?;
    Ok(u16::from_be_bytes(port))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn negotiate_accepts_no_auth_by_default() {
        let (mut server_stream, mut client) = socks_pair().await;
        let server = tokio::spawn(async move { negotiate(&mut server_stream, None).await });

        client
            .write_all(&[SOCKS_VERSION, 1, SOCKS_METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]);

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
            .write_all(&[SOCKS_VERSION, 1, SOCKS_METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]);

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
                SOCKS_METHOD_NO_AUTH,
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
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_METHOD_NO_AUTH]);

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
                SOCKS_METHOD_USERNAME_PASSWORD,
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
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_METHOD_USERNAME_PASSWORD]);

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
                SOCKS_METHOD_NO_AUTH,
                SOCKS_METHOD_USERNAME_PASSWORD,
            ])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_METHOD_USERNAME_PASSWORD]);

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
            .write_all(&[SOCKS_VERSION, 1, SOCKS_METHOD_USERNAME_PASSWORD])
            .await
            .unwrap();
        let mut method_reply = [0u8; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [SOCKS_VERSION, SOCKS_METHOD_USERNAME_PASSWORD]);

        client
            .write_all(&[0x01, 5, b'a', b'l', b'i', b'c', b'e', 5, b'w', b'r', b'o', b'n', b'g'])
            .await
            .unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x01]);

        let err = server.await.unwrap().unwrap_err();
        assert!(matches!(err, Socks5Error::InvalidCredentials));
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
