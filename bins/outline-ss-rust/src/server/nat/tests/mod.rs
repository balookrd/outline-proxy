use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use bytes::Bytes;
use futures_util::future::BoxFuture;

use super::super::constants::MAX_UDP_PAYLOAD_SIZE;
use super::reader::record_oversized_socket_response_drop;
use super::{NatKey, NatTable, ResponseSender, UdpResponseSender};
use crate::{
    config::{CipherKind, Config},
    crypto::{UdpCipherMode, UserKey},
    metrics::{Metrics, Protocol},
};

/// Minimal `ResponseSender` double used to exercise the NAT layer without
/// pulling in the WebSocket/H3 transport crates.
struct TestResponseSender {
    protocol: Protocol,
}

impl ResponseSender for TestResponseSender {
    fn send_bytes(&self, _data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn app_protocol(&self) -> crate::metrics::AppProtocol {
        crate::metrics::AppProtocol::Shadowsocks
    }
}

fn test_sender(protocol: Protocol) -> UdpResponseSender {
    UdpResponseSender::new(Arc::new(TestResponseSender { protocol }))
}

#[tokio::test]
async fn drops_oversized_socket_udp_response_and_records_metric() -> Result<()> {
    let config = Config {
        listen: Some("127.0.0.1:3000".parse().unwrap()),
        tls_cert_path: None,
        tls_key_path: None,
        tls_certs: Vec::new(),
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_certs: Vec::new(),
        h3_alpn: vec![crate::config::H3Alpn::H3],
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
        users: vec![],
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
    };
    let metrics = Metrics::new(&config);
    let user = UserKey::new("bob", "secret-b", None, CipherKind::Chacha20IetfPoly1305, None)?;
    let sender = test_sender(Protocol::Socket);

    assert!(record_oversized_socket_response_drop(
        Some(&sender),
        metrics.as_ref(),
        &user,
        SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)),
        MAX_UDP_PAYLOAD_SIZE + 1,
    ));

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains(
        "outline_ss_udp_oversized_datagrams_dropped_total{user=\"bob\",protocol=\"socket\",app_protocol=\"shadowsocks\",direction=\"target_to_client\"} 1"
    ));
    Ok(())
}

#[test]
fn ignores_non_socket_or_in_range_udp_response_sizes() -> Result<()> {
    let config = Config {
        listen: Some("127.0.0.1:3000".parse().unwrap()),
        tls_cert_path: None,
        tls_key_path: None,
        tls_certs: Vec::new(),
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_certs: Vec::new(),
        h3_alpn: vec![crate::config::H3Alpn::H3],
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
        users: vec![],
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
    };
    let metrics = Metrics::new(&config);
    let user = UserKey::new("bob", "secret-b", None, CipherKind::Chacha20IetfPoly1305, None)?;
    let ws_sender = test_sender(Protocol::Http2);

    assert!(!record_oversized_socket_response_drop(
        Some(&ws_sender),
        metrics.as_ref(),
        &user,
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        MAX_UDP_PAYLOAD_SIZE + 1,
    ));
    assert!(!record_oversized_socket_response_drop(
        Some(&ws_sender),
        metrics.as_ref(),
        &user,
        SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        MAX_UDP_PAYLOAD_SIZE,
    ));
    Ok(())
}

#[tokio::test]
async fn deduplicates_concurrent_nat_entry_creation() -> Result<()> {
    let config = Config {
        listen: Some("127.0.0.1:3000".parse().unwrap()),
        tls_cert_path: None,
        tls_key_path: None,
        tls_certs: Vec::new(),
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_certs: Vec::new(),
        h3_alpn: vec![crate::config::H3Alpn::H3],
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
        users: vec![],
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
    };
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(Duration::from_secs(300));
    let user = UserKey::new("bob", "secret-b", None, CipherKind::Chacha20IetfPoly1305, None)?;
    let key = NatKey {
        user_id: user.id_arc(),
        fwmark: None,
        target: SocketAddr::from((Ipv4Addr::LOCALHOST, 5300)),
    };

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let nat_table = Arc::clone(&nat_table);
        let user = user.clone();
        let key = key.clone();
        let metrics = Arc::clone(&metrics);
        tasks.push(tokio::spawn(async move {
            nat_table
                .get_or_create(key, &user, UdpCipherMode::Legacy, metrics)
                .await
        }));
    }

    let mut entries = Vec::new();
    for task in tasks {
        entries.push(task.await??);
    }

    assert_eq!(nat_table.len(), 1);
    for entry in entries.iter().skip(1) {
        assert!(Arc::ptr_eq(&entries[0], entry));
    }

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("outline_ss_udp_nat_entries_created_total 1"));
    assert!(rendered.contains("outline_ss_udp_nat_active_entries 1"));
    Ok(())
}

#[tokio::test]
async fn caps_live_entries_and_records_capacity_drop() -> Result<()> {
    let config = Config {
        listen: Some("127.0.0.1:3000".parse().unwrap()),
        tls_cert_path: None,
        tls_key_path: None,
        tls_certs: Vec::new(),
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_certs: Vec::new(),
        h3_alpn: vec![crate::config::H3Alpn::H3],
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
        users: vec![],
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
    };
    let metrics = Metrics::new(&config);
    // Cap of 2 live entries; `0` would disable the cap.
    let nat_table = NatTable::with_outbound_ipv6(Duration::from_secs(300), 2, None);
    let user = UserKey::new("cap", "secret-c", None, CipherKind::Chacha20IetfPoly1305, None)?;

    // Two distinct targets fill the table to capacity.
    for port in [6001u16, 6002] {
        let key = NatKey {
            user_id: user.id_arc(),
            fwmark: None,
            target: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        };
        nat_table
            .get_or_create(key, &user, UdpCipherMode::Legacy, Arc::clone(&metrics))
            .await?;
    }
    assert_eq!(nat_table.len(), 2);

    // A third *new* target is rejected while the table is at capacity.
    let overflow_key = NatKey {
        user_id: user.id_arc(),
        fwmark: None,
        target: SocketAddr::from((Ipv4Addr::LOCALHOST, 6003)),
    };
    let rejected = nat_table
        .get_or_create(overflow_key, &user, UdpCipherMode::Legacy, Arc::clone(&metrics))
        .await;
    assert!(rejected.is_err(), "a new target must be rejected at capacity");
    assert_eq!(nat_table.len(), 2, "a rejected datagram must not add an entry");

    // An already-live target still resolves to its existing entry, even when full.
    let live_key = NatKey {
        user_id: user.id_arc(),
        fwmark: None,
        target: SocketAddr::from((Ipv4Addr::LOCALHOST, 6001)),
    };
    nat_table
        .get_or_create(live_key, &user, UdpCipherMode::Legacy, Arc::clone(&metrics))
        .await?;
    assert_eq!(nat_table.len(), 2);

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("outline_ss_udp_nat_capacity_dropped_total 1"));
    Ok(())
}
