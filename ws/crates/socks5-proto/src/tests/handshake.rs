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
