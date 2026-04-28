use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::http::header;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::UdpSocket;

use super::nat::NatTable;
use super::setup::{UserRoute, build_vless_transport_route_map};
use super::state::{RoutesSnapshot, UserKeySlice};
use super::{
    AuthPolicy, DnsCache, RouteRegistry, Services, UdpServices, build_transport_route_map,
    user_keys,
};
use crate::config::{CipherKind, Config, UserEntry};
use crate::crypto::{decrypt_udp_packet, encrypt_udp_packet};
use crate::metrics::{Metrics, Transport};
use crate::protocol::TargetAddr;
use arc_swap::ArcSwap;

mod auth;
mod connect;
mod dns_cache;
mod h3;
mod nat;
mod raw_quic;
mod resumption;
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
) -> (RoutesSnapshot, Arc<Services>, Arc<AuthPolicy>) {
    let users = user_keys(user_routes.as_ref());
    let tcp = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    let vless = Arc::new(build_vless_transport_route_map(&[]));
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry { tcp, udp, vless }));
    let services = Arc::new(Services::new(
        metrics,
        dns_cache,
        false,
        None,
        UdpServices {
            nat_table,
            replay_store: super::replay::ReplayStore::new(std::time::Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        None,
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth,
        http_root_realm: http_root_realm.into(),
    });
    (routes, services, auth)
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
            ws_path_vless: None,
            enabled: None,
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
        h3_alpn: vec![crate::config::H3Alpn::H3],
        metrics_listen: None,
        metrics_path: "/metrics".into(),
        prefer_ipv4_upstream: false,
        outbound_ipv6_prefix: None,
        outbound_ipv6_interface: None,
        outbound_ipv6_refresh_secs: 30,
        ws_path_tcp: "/tcp".into(),
        ws_path_udp: "/udp".into(),
        ws_path_vless: None,
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
        users,
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: Default::default(),
        session_resumption: Default::default(),
        config_path: None,
        control: None,
        dashboard: None,
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
