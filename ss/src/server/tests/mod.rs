use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use axum::http::header;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

use super::connect::{connect_tcp_addrs, connect_tcp_target, sort_addrs_for_happy_eyeballs};
use super::nat::NatTable;
use super::setup::{UserRoute, build_vless_transport_route_map};
use super::{
    AuthPolicy, DnsCache, RouteRegistry, Services, UdpServices, build_transport_route_map,
    user_keys,
};
use crate::config::{CipherKind, Config, UserEntry};
use crate::crypto::{decrypt_udp_packet, encrypt_udp_packet};
use crate::metrics::{Metrics, Transport};
use crate::protocol::TargetAddr;

mod auth;
mod h3;
mod nat;
mod shadowsocks;
mod vless;
mod websocket;

fn build_test_state(
    user_routes: Arc<[UserRoute]>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    http_root_auth: bool,
    http_root_realm: impl Into<Arc<str>>,
) -> (Arc<RouteRegistry>, Arc<Services>, Arc<AuthPolicy>) {
    let users = user_keys(user_routes.as_ref());
    let tcp = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    let vless = Arc::new(build_vless_transport_route_map(&[]));
    let routes = Arc::new(RouteRegistry { tcp, udp, vless });
    let services = Arc::new(Services {
        metrics,
        dns_cache,
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
        udp: UdpServices {
            nat_table,
            replay_store: super::replay::ReplayStore::new(std::time::Duration::from_secs(300)),
            relay_semaphore: None,
        },
    });
    let auth = Arc::new(AuthPolicy {
        users,
        http_root_auth,
        http_root_realm: http_root_realm.into(),
    });
    (routes, services, auth)
}

#[tokio::test]
async fn tcp_ipv6_loopback_smoke() -> Result<()> {
    let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(listener) => listener,
        Err(error) if ipv6_unavailable(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf)
    });

    let target = TargetAddr::Socket(SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let mut client = connect_tcp_target(dns_cache.as_ref(), &target, None, false, None).await?;
    client.write_all(b"ping").await?;

    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).await?;

    assert_eq!(&reply, b"pong");
    assert_eq!(server.await??, *b"ping");
    Ok(())
}

#[test]
fn tcp_connect_order_interleaves_ipv4_and_ipv6() {
    let ordered = sort_addrs_for_happy_eyeballs(
        vec![
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
        ],
        false,
    );

    assert_eq!(
        ordered,
        vec![
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
        ]
    );
}

#[test]
fn dns_cache_returns_fresh_entries_and_expires() {
    let cache = DnsCache::new(std::time::Duration::from_millis(5));
    let resolved = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
    let entry: Arc<[SocketAddr]> = Arc::from(vec![resolved].into_boxed_slice());

    cache.store("dns.google", 53, false, entry);
    assert_eq!(cache.lookup_one("dns.google", 53, false), Some(resolved));

    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_eq!(cache.lookup_one("dns.google", 53, false), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_cache_singleflight_coalesces_concurrent_misses() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cache = DnsCache::new(std::time::Duration::from_secs(30));
    let invocations = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(16));

    let resolved: Arc<[SocketAddr]> =
        Arc::from(vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 443))].into_boxed_slice());

    let mut handles = Vec::new();
    for _ in 0..16 {
        let cache = Arc::clone(&cache);
        let invocations = Arc::clone(&invocations);
        let barrier = Arc::clone(&barrier);
        let resolved = Arc::clone(&resolved);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            cache
                .resolve_or_join("slow.example", 443, false, |cache| {
                    let invocations = Arc::clone(&invocations);
                    let resolved = Arc::clone(&resolved);
                    async move {
                        invocations.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        cache.store("slow.example", 443, false, Arc::clone(&resolved));
                        Ok(resolved)
                    }
                })
                .await
                .expect("resolve succeeds")
        }));
    }

    for handle in handles {
        let addrs = handle.await.expect("task joins");
        assert_eq!(addrs.as_ref(), resolved.as_ref());
    }

    assert_eq!(invocations.load(Ordering::SeqCst), 1, "loader must run once");
}

#[tokio::test]
async fn dns_cache_singleflight_propagates_errors() {
    let cache = DnsCache::new(std::time::Duration::from_secs(30));
    let err = cache
        .resolve_or_join(
            "fail.example",
            443,
            false,
            |_| async move { Err(anyhow::anyhow!("boom")) },
        )
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("boom"));

    let resolved: Arc<[SocketAddr]> =
        Arc::from(vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 1))].into_boxed_slice());
    let resolved2 = Arc::clone(&resolved);
    let ok = cache
        .resolve_or_join("fail.example", 443, false, move |_| {
            let resolved2 = Arc::clone(&resolved2);
            async move { Ok(resolved2) }
        })
        .await
        .expect("second call succeeds");
    assert_eq!(ok.as_ref(), resolved.as_ref());
}

#[tokio::test]
async fn tcp_connect_tries_next_resolved_address() -> Result<()> {
    let blocked_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let blocked_addr = blocked_listener.local_addr()?;
    drop(blocked_listener);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf)
    });

    let mut client = connect_tcp_addrs(&[blocked_addr, addr], None, None).await?;
    client.write_all(b"ping").await?;

    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).await?;

    assert_eq!(&reply, b"pong");
    assert_eq!(server.await??, *b"ping");
    Ok(())
}

#[tokio::test]
async fn udp_ipv6_loopback_smoke() -> Result<()> {
    let echo = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(s) => s,
        Err(error) if ipv6_unavailable(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let echo_addr = echo.local_addr()?;
    let server = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = echo.recv_from(&mut buf).await?;
        echo.send_to(&buf[..read], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
    });

    let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
    client.send_to(b"ping", echo_addr).await?;
    let mut buf = [0_u8; 64];
    let (read, source) =
        tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf))
            .await??;

    assert_eq!(source.ip(), Ipv6Addr::LOCALHOST);
    assert_eq!(&buf[..read], b"ping");
    assert_eq!(server.await??, b"ping");
    Ok(())
}

fn ipv6_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
    )
}

fn sample_config(listen: SocketAddr) -> Config {
    sample_config_with_users(
        listen,
        vec![UserEntry {
            id: "bob".into(),
            password: Some("secret-b".into()),
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: None,
            vless_ws_path: None,
        }],
    )
}

fn sample_config_with_users(listen: SocketAddr, users: Vec<UserEntry>) -> Config {
    Config {
        listen: Some(listen),
        ss_listen: None,
        tls_cert_path: None,
        tls_key_path: None,
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        metrics_listen: None,
        metrics_path: "/metrics".into(),
        prefer_ipv4_upstream: false,
        outbound_ipv6_prefix: None,
        outbound_ipv6_interface: None,
        outbound_ipv6_refresh_secs: 30,
        ws_path_tcp: "/tcp".into(),
        ws_path_udp: "/udp".into(),
        vless_ws_path: None,
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
        password: None,
        fwmark: None,
        users,
        method: CipherKind::Chacha20IetfPoly1305,
        tuning: Default::default(),
    }
}

fn basic_auth_header(password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("ignored:{password}")))
}

fn set_cookie_pair<T>(response: &axum::http::Response<T>) -> Result<String> {
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .context("missing set-cookie header")?
        .to_str()?
        .split(';')
        .next()
        .context("invalid set-cookie header")?
        .to_owned())
}

async fn send_encrypted_udp_request(
    client: &UdpSocket,
    listen_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
    user: &crate::crypto::UserKey,
) -> Result<()> {
    let mut plaintext = TargetAddr::Socket(target).encode()?;
    plaintext.extend_from_slice(payload);
    let ciphertext = encrypt_udp_packet(user, &plaintext)?;
    client.send_to(&ciphertext, listen_addr).await?;
    Ok(())
}

async fn recv_decrypted_udp_response(
    client: &UdpSocket,
    user: &crate::crypto::UserKey,
) -> Result<Vec<u8>> {
    let mut encrypted_reply = [0_u8; 65_535];
    let (read, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut encrypted_reply),
    )
    .await??;

    let packet = decrypt_udp_packet(std::slice::from_ref(user), &encrypted_reply[..read])?;
    let (_, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
        .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
    Ok(packet.payload[consumed..].to_vec())
}

fn test_h3_server_tls() -> Result<(rustls::ServerConfig, CertificateDer<'static>)> {
    super::ensure_rustls_provider_installed();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    Ok((tls_config, cert_der))
}

fn test_h3_client_config(cert_der: CertificateDer<'static>) -> Result<quinn::ClientConfig> {
    super::ensure_rustls_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

fn write_test_h2_tls_cert()
-> Result<(std::path::PathBuf, std::path::PathBuf, CertificateDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_pem = cert.cert.pem();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_pem = cert.signing_key.serialize_pem();
    let base = std::env::temp_dir().join(format!(
        "outline-ss-rust-h2-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let cert_path = base.with_extension("crt.pem");
    let key_path = base.with_extension("key.pem");
    std::fs::write(&cert_path, cert_pem)?;
    std::fs::write(&key_path, key_pem)?;
    Ok((cert_path, key_path, cert_der))
}
