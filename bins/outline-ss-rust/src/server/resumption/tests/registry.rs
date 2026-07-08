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
        tls_cert_path: None,
        tls_key_path: None,
        tls_certs: Vec::new(),
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_certs: Vec::new(),
        h3_alpn: vec![H3Alpn::H3],
        metrics_listen: None,
        metrics_path: "/metrics".into(),
        prefer_ipv4_upstream: false,
        outbound_ipv6_prefix: None,
        outbound_ipv6_interface: None,
        outbound_ipv6_prefix_interface: None,
        outbound_ipv6_refresh_secs: 30,
        outbound_ipv6_sticky: false,
        outbound_ipv6_sticky_ttl_secs: 1800,
        ws_path_tcp: "/tcp".into(),
        ws_path_udp: "/udp".into(),
        ws_path_ss: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
        users: vec![UserEntry {
            id: "u1".into(),
            password: Some("secret".into()),
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            ws_path_ss: None,
            vless_id: None,
            ws_path_vless: None,
            xhttp_path_vless: None,
            xhttp_path_tcp: None,
            xhttp_path_udp: None,
            xhttp_path_ss: None,
            enabled: None,
            aliases: None,
        }],
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: Default::default(),
        session_resumption: Default::default(),
        padding: Default::default(),
        http_fallback: None,
        sni_fallback: None,
        cluster: None,
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
    UserKey::new(id, "secret-pass", None, CipherKind::Chacha20IetfPoly1305, None).unwrap()
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
        // Counter is registry-level data; tests of the registry itself
        // don't exercise the Ack-Prefix relay path, just need a sane
        // initial value.
        upstream_bytes_acked: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        // Registry tests never touch the v2 Symmetric Downlink Replay
        // ring; absence (`None`) is the same shape the registry sees
        // for any session whose carrier doesn't activate v2.
        downlink_ring: None,
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
async fn mint_with_cluster_encodes_shard() {
    let metrics = Metrics::new(&test_config());
    let key = ObfuscationKey::derive_from_psk(b"registry-cluster-psk");
    let shard = ShardId::new(7).unwrap();
    let registry = OrphanRegistry::new(enabled_config(), metrics).with_cluster(key.clone(), shard);
    // Every minted id round-trips to this server's own shard.
    for _ in 0..8 {
        let id = registry.mint_session_id().unwrap();
        assert_eq!(id.shard(&key).get(), 7);
    }
}

#[tokio::test]
async fn park_then_take_returns_payload_for_owner() {
    let metrics = Metrics::new(&test_config());
    let registry = OrphanRegistry::new(enabled_config(), metrics.clone());
    let id = registry.mint_session_id().unwrap();
    let parked = make_parked_tcp(&metrics, "u1").await;
    registry.park(id, parked);
    assert_eq!(registry.len(), 1);

    let outcome = registry.take_for_resume(id, "u1").await;
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

    let outcome = registry.take_for_resume(id, "mallory").await;
    assert!(matches!(outcome, ResumeOutcome::Miss(ResumeMiss::OwnerMismatch)));
    // The entry stays parked so its rightful owner can still claim it.
    assert_eq!(registry.len(), 1);

    let outcome = registry.take_for_resume(id, "alice").await;
    assert!(matches!(outcome, ResumeOutcome::Hit(Parked::Tcp(_))));
}

#[tokio::test]
async fn unknown_id_misses() {
    let metrics = Metrics::new(&test_config());
    let registry = OrphanRegistry::new(enabled_config(), metrics);
    let outcome = registry
        .take_for_resume(SessionId::from_bytes([7u8; 16]), "anyone")
        .await;
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
        registry.take_for_resume(id1, "u1").await,
        ResumeOutcome::Miss(ResumeMiss::Unknown)
    ));
    assert!(matches!(registry.take_for_resume(id2, "u1").await, ResumeOutcome::Hit(_)));
    assert!(matches!(registry.take_for_resume(id3, "u1").await, ResumeOutcome::Hit(_)));
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

/// A resume that arrives while a park is still in flight (reserved but not yet
/// committed) waits for the park to land and then hits, instead of missing and
/// forcing a fresh session. This is the park-miss race fix.
#[tokio::test]
async fn resume_waits_for_in_flight_park() {
    let metrics = Metrics::new(&test_config());
    let registry = Arc::new(OrphanRegistry::new(enabled_config(), metrics.clone()));
    let id = registry.mint_session_id().unwrap();

    // Reserve the id as the parking side does before its reader harvest, but do
    // not commit the park yet.
    let reservation = registry.reserve_park(id);

    // A concurrent resume must not miss: it blocks on the reservation.
    let r2 = Arc::clone(&registry);
    let resume =
        tokio::spawn(
            async move { matches!(r2.take_for_resume(id, "u1").await, ResumeOutcome::Hit(_)) },
        );

    // Let the resume task reach its wait, then land the park and drop the guard
    // (the real parking side commits, then the reservation guard drops).
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!resume.is_finished(), "resume must block while the park is in flight");
    registry.park(id, make_parked_tcp(&metrics, "u1").await);
    drop(reservation);

    assert!(resume.await.unwrap(), "resume must hit the just-committed park");
    assert_eq!(registry.len(), 0);
}

/// If the in-flight park is abandoned (the reservation guard drops without a
/// commit — e.g. the reader harvest found nothing worth parking), the waiting
/// resume wakes and misses rather than hanging.
#[tokio::test]
async fn resume_misses_when_reserved_park_is_abandoned() {
    let metrics = Metrics::new(&test_config());
    let registry = Arc::new(OrphanRegistry::new(enabled_config(), metrics));
    let id = registry.mint_session_id().unwrap();
    let reservation = registry.reserve_park(id);

    let r2 = Arc::clone(&registry);
    let resume = tokio::spawn(async move {
        matches!(r2.take_for_resume(id, "u1").await, ResumeOutcome::Miss(ResumeMiss::Unknown))
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!resume.is_finished(), "resume must block while the id is reserved");
    drop(reservation); // abandon the park without committing

    assert!(resume.await.unwrap(), "resume must miss once the park is abandoned");
    assert_eq!(registry.len(), 0);
}
