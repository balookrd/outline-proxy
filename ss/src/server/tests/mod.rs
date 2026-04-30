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
mod cross_repo_ss;
mod cross_repo_vless;
mod cross_repo_xhttp;
mod dns_cache;
mod h3;
mod nat;
mod raw_quic;
mod resumption;
mod shadowsocks;
mod vless;
mod websocket;
mod xhttp;

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
    let xhttp_vless = Arc::new(std::collections::BTreeMap::new());
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp,
        udp,
        vless,
        xhttp_vless,
    }));
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
            xhttp_path_vless: None,
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
        xhttp_path_vless: None,
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

/// Lazy, process-wide self-signed cert reused by every cross-repo
/// integration test that needs TLS. Returns DER-encoded cert + key
/// bytes plus an owned `CertificateDer<'static>`. Building the
/// `rustls::ServerConfig` is left to each test (h3 / h2 / vless /
/// ss ALPN sets differ); the bytes themselves are shared so that
/// `outline_transport::install_test_tls_root` — which is
/// last-writer-wins — pins the same root for every dial in this
/// process.
/// Process-wide CA + leaf cert pair reused by every cross-repo
/// integration test that needs TLS. Split because webpki (used by
/// `tokio_rustls`) rejects a single self-signed leaf installed as
/// a trust root with `CaUsedAsEndEntity`; quinn's verifier is
/// laxer but we want the same fixture to satisfy both.
///
/// Tuple shape: `(ca_cert_der, leaf_cert_der, leaf_key_der,
/// owned_ca_der)`. Server-side `ServerConfig` is built from the
/// leaf cert + key; the client's trust override is installed with
/// the CA cert.
pub(super) fn cross_repo_shared_test_cert()
-> &'static (Vec<u8>, Vec<u8>, Vec<u8>, CertificateDer<'static>) {
    static CELL: std::sync::OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>, CertificateDer<'static>)> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        super::ensure_rustls_provider_installed();
        // CA: self-signed, marked as a real CA so webpki accepts
        // it as a trust anchor.
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("rcgen CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "outline-cross-repo-test-ca");
        let ca_key = rcgen::KeyPair::generate().expect("rcgen CA KeyPair");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("rcgen CA self-signed");
        let ca_der = ca_cert.der().to_vec();
        // Leaf: signed by the CA above, SAN = `localhost`.
        let leaf_params = rcgen::CertificateParams::new(vec!["localhost".into()])
            .expect("rcgen leaf params");
        let leaf_key = rcgen::KeyPair::generate().expect("rcgen leaf KeyPair");
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("rcgen leaf signed by CA");
        let leaf_der = leaf_cert.der().to_vec();
        let leaf_key_der = leaf_key.serialize_der();
        let ca_cert_der = CertificateDer::from(ca_der.clone());
        let _ = ca_cert; // silence unused warning — kept for clarity
        (ca_der, leaf_der, leaf_key_der, ca_cert_der)
    })
}

/// Builds a fresh `rustls::ServerConfig` for the shared cross-repo
/// cert with the given ALPN list. `H3WebSocketServer::bind` and
/// the axum-over-TLS test path both consume the config by value,
/// so each test rebuilds its own from the cached cert/key bytes.
pub(super) fn cross_repo_test_server_tls_config(alpn: &[&[u8]]) -> rustls::ServerConfig {
    let (_, leaf_bytes, key_bytes, _) = cross_repo_shared_test_cert();
    let leaf_der = CertificateDer::from(leaf_bytes.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes.clone()));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf_der], key)
        .expect("test server tls config");
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

/// Installs the shared self-signed root into the client's TLS
/// override slot exactly once per process. Idempotent on its own,
/// and `install_test_tls_root` is also idempotent if called
/// repeatedly with the same cert.
pub(super) fn cross_repo_install_test_tls_root_on_client() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let (_, _, _, ca_der) = cross_repo_shared_test_cert();
        outline_transport::install_test_tls_root(ca_der.clone());
    });
}

/// Minimal axum-over-TLS serve loop for cross-repo fallback tests.
/// Mirrors `crate::server::bootstrap::axum::serve_tls_listener` in
/// shape but skips the production hardening (semaphores, JoinSet
/// drain, TuningProfile windows) — tests don't need any of that
/// and dragging the prod helper through `pub(in crate::server)`
/// would be more invasive than it's worth. RFC 8441 (WebSocket
/// over h2) needs `enable_connect_protocol` on the h2 builder, so
/// the h2-TLS path mounts the same WS upgrade route as plain TCP.
pub(super) async fn cross_repo_serve_axum_with_tls(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    acceptor: tokio_rustls::TlsAcceptor,
) -> anyhow::Result<()> {
    use hyper_util::{
        rt::{TokioExecutor, TokioIo, TokioTimer},
        server::conn::auto,
        service::TowerToHyperService,
    };
    use std::net::SocketAddr;

    loop {
        let (tcp, peer_addr): (_, SocketAddr) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(_) => return,
            };
            // Inject `ConnectInfo<SocketAddr>` so the WS upgrade
            // handler keys the same per-route peer-user cache the
            // production listener uses.
            let app_with_addr =
                app.layer(axum::Extension(axum::extract::ConnectInfo(peer_addr)));
            let svc = TowerToHyperService::new(app_with_addr);
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http2()
                .timer(TokioTimer::new())
                .enable_connect_protocol();
            let _ = builder.serve_connection_with_upgrades(TokioIo::new(tls), svc).await;
        });
    }
}

/// Plain-TCP, h1-only serve loop for cross-repo h2→h1 fallback
/// tests. Drives the dispatcher's WsH2 → WsH1 downgrade: a client
/// dialing with `TransportMode::WsH2` opens a TCP connection and
/// writes the h2 preface (`PRI * HTTP/2.0\r\n…`); h1-only hyper
/// rejects it as a malformed h1 request, the dispatcher records the
/// failure and retries on h1 with the same `X-Outline-Resume`
/// header. No TLS — `ws://` URL keeps tungstenite happy and avoids
/// the webpki / override mismatch on the h1 path (tungstenite uses
/// its own webpki bundle for `wss://`, which would not see our
/// shared self-signed root).
pub(super) async fn cross_repo_serve_axum_h1_only(
    listener: tokio::net::TcpListener,
    app: axum::Router,
) -> anyhow::Result<()> {
    use hyper_util::{rt::TokioIo, service::TowerToHyperService};
    use std::net::SocketAddr;

    loop {
        let (tcp, peer_addr): (_, SocketAddr) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let app = app.clone();
        tokio::spawn(async move {
            let app_with_addr =
                app.layer(axum::Extension(axum::extract::ConnectInfo(peer_addr)));
            let svc = TowerToHyperService::new(app_with_addr);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), svc)
                .with_upgrades()
                .await;
        });
    }
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
