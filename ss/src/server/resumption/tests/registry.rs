use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::net::{TcpListener, TcpStream};

use crate::{
    config::{CipherKind, Config, H3Alpn, UserEntry},
    crypto::UserKey,
    metrics::{AppProtocol, Metrics, Protocol},
};

use super::super::parked::{Parked, ParkedTcp, TcpProtocolContext};
use super::*;

fn test_config() -> Config {
    Config {
        listen: Some("127.0.0.1:3000".parse().unwrap()),
        ss_listen: None,
        tls_cert_path: None,
        tls_key_path: None,
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_alpn: vec![H3Alpn::H3],
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
        users: vec![UserEntry {
            id: "u1".into(),
            password: Some("secret".into()),
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: None,
            ws_path_vless: None,
            xhttp_path_vless: None,
            enabled: None,
        }],
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: Default::default(),
        session_resumption: Default::default(),
        config_path: None,
        control: None,
        dashboard: None,
    }
}

fn enabled_config() -> ResumptionConfig {
    ResumptionConfig {
        enabled: true,
        ..ResumptionConfig::defaults_disabled()
    }
}

async fn loopback_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (incoming, outgoing) =
        tokio::join!(async { listener.accept().await.unwrap().0 }, TcpStream::connect(addr));
    (incoming, outgoing.unwrap())
}

fn make_user(id: &str) -> UserKey {
    UserKey::new(id, "secret-pass", None, CipherKind::Chacha20IetfPoly1305).unwrap()
}

async fn make_parked_tcp(metrics: &Arc<Metrics>, owner: &str) -> Parked {
    let (a, _b) = loopback_tcp_pair().await;
    let (reader, writer) = a.into_split();
    let user = make_user(owner);
    let user_id = user.id_arc();
    Parked::Tcp(ParkedTcp {
        upstream_writer: writer,
        upstream_reader: reader,
        target_display: Arc::from("example.com:443"),
        owner: Arc::clone(&user_id),
        protocol_context: TcpProtocolContext::Ss(user),
        user_counters: metrics.user_counters(&user_id),
        upstream_guard: metrics.open_tcp_upstream_connection(
            user_id,
            Protocol::Http2,
            AppProtocol::Shadowsocks,
        ),
    })
}

#[tokio::test]
async fn disabled_registry_drops_park_silently() {
    let metrics = Metrics::new(&test_config());
    let registry = OrphanRegistry::new(ResumptionConfig::defaults_disabled(), metrics.clone());
    assert!(!registry.enabled());
    assert!(registry.mint_session_id().is_none());
    let parked = make_parked_tcp(&metrics, "u1").await;
    registry.park(SessionId::from_bytes([0u8; 16]), parked);
    assert_eq!(registry.len(), 0);
}

#[tokio::test]
async fn park_then_take_returns_payload_for_owner() {
    let metrics = Metrics::new(&test_config());
    let registry = OrphanRegistry::new(enabled_config(), metrics.clone());
    let id = registry.mint_session_id().unwrap();
    let parked = make_parked_tcp(&metrics, "u1").await;
    registry.park(id, parked);
    assert_eq!(registry.len(), 1);

    let outcome = registry.take_for_resume(id, "u1");
    assert!(matches!(outcome, ResumeOutcome::Hit(Parked::Tcp(_))));
    assert_eq!(registry.len(), 0);
}

#[tokio::test]
async fn take_with_wrong_owner_keeps_entry_and_reports_mismatch() {
    let metrics = Metrics::new(&test_config());
    let registry = OrphanRegistry::new(enabled_config(), metrics.clone());
    let id = registry.mint_session_id().unwrap();
    let parked = make_parked_tcp(&metrics, "alice").await;
    registry.park(id, parked);

    let outcome = registry.take_for_resume(id, "mallory");
    assert!(matches!(outcome, ResumeOutcome::Miss(ResumeMiss::OwnerMismatch)));
    // The entry stays parked so its rightful owner can still claim it.
    assert_eq!(registry.len(), 1);

    let outcome = registry.take_for_resume(id, "alice");
    assert!(matches!(outcome, ResumeOutcome::Hit(Parked::Tcp(_))));
}

#[tokio::test]
async fn unknown_id_misses() {
    let metrics = Metrics::new(&test_config());
    let registry = OrphanRegistry::new(enabled_config(), metrics);
    let outcome = registry.take_for_resume(SessionId::from_bytes([7u8; 16]), "anyone");
    assert!(matches!(outcome, ResumeOutcome::Miss(ResumeMiss::Unknown)));
}

#[tokio::test]
async fn per_user_cap_evicts_oldest() {
    let metrics = Metrics::new(&test_config());
    let cfg = ResumptionConfig {
        enabled: true,
        orphan_per_user_cap: 2,
        ..ResumptionConfig::defaults_disabled()
    };
    let registry = OrphanRegistry::new(cfg, metrics.clone());
    let id1 = registry.mint_session_id().unwrap();
    let id2 = registry.mint_session_id().unwrap();
    let id3 = registry.mint_session_id().unwrap();
    registry.park(id1, make_parked_tcp(&metrics, "u1").await);
    registry.park(id2, make_parked_tcp(&metrics, "u1").await);
    registry.park(id3, make_parked_tcp(&metrics, "u1").await);

    assert_eq!(registry.len(), 2, "oldest entry must have been evicted");
    assert!(matches!(
        registry.take_for_resume(id1, "u1"),
        ResumeOutcome::Miss(ResumeMiss::Unknown)
    ));
    assert!(matches!(registry.take_for_resume(id2, "u1"), ResumeOutcome::Hit(_)));
    assert!(matches!(registry.take_for_resume(id3, "u1"), ResumeOutcome::Hit(_)));
}

#[tokio::test]
async fn sweep_drops_expired_entries() {
    let metrics = Metrics::new(&test_config());
    let cfg = ResumptionConfig {
        enabled: true,
        orphan_ttl_tcp: Duration::from_millis(20),
        ..ResumptionConfig::defaults_disabled()
    };
    let registry = OrphanRegistry::new(cfg, metrics.clone());
    let id = registry.mint_session_id().unwrap();
    registry.park(id, make_parked_tcp(&metrics, "u1").await);
    assert_eq!(registry.len(), 1);

    tokio::time::sleep(Duration::from_millis(40)).await;
    let removed = registry.sweep_expired();
    assert_eq!(removed, 1);
    assert_eq!(registry.len(), 0);
}
