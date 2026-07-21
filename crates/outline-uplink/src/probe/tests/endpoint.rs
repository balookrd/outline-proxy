//! Tests for the endpoint-reachability check.
//!
//! Endpoint collection is pure and tested directly. The connect path is
//! exercised against a real loopback listener — cheap, and the only way to
//! cover the distinction the check exists to draw: "something is listening"
//! vs "nothing is".

use std::time::Duration;

use tokio::net::TcpListener;

use outline_transport::DnsCache;

use super::{unreachable_uplink_endpoints, uplink_endpoints};

use crate::config::{CipherKind, FallbackTransport, TransportMode, UplinkConfig, UplinkTransport};

fn ss_ws_uplink(tcp_url: &str) -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(url::Url::parse(tcp_url).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

fn ws_fallback(tcp_url: &str) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(url::Url::parse(tcp_url).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

#[test]
fn wires_sharing_one_host_and_port_collapse_to_a_single_endpoint() {
    // The common shape: primary and every fallback are different carriers on
    // the same server. One connect answers for all of them.
    let mut cfg = ss_ws_uplink("wss://edge.example.com:6443/ws");
    cfg.fallbacks = vec![ws_fallback("wss://edge.example.com:6443/ws2")];

    let endpoints = uplink_endpoints(&cfg);

    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].label(), "edge.example.com:6443");
}

#[test]
fn a_fallback_on_another_host_is_its_own_endpoint() {
    let mut cfg = ss_ws_uplink("wss://edge.example.com:6443/ws");
    cfg.fallbacks = vec![ws_fallback("wss://spare.example.com:443/ws")];

    let labels: Vec<String> = uplink_endpoints(&cfg).iter().map(|e| e.label()).collect();

    assert_eq!(labels, vec!["edge.example.com:6443", "spare.example.com:443"]);
}

#[test]
fn scheme_default_port_is_resolved() {
    // `wss://host/path` dials 443 — the label must say so, since it is what
    // the connect targets and what the operator reads in `last_error`.
    let cfg = ss_ws_uplink("wss://edge.example.com/ws");

    assert_eq!(uplink_endpoints(&cfg)[0].label(), "edge.example.com:443");
}

#[tokio::test]
async fn a_listening_endpoint_is_reachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = ss_ws_uplink(&format!("ws://127.0.0.1:{port}/ws"));

    let verdict =
        unreachable_uplink_endpoints(&DnsCache::default(), "test", &cfg, Duration::from_secs(2))
            .await;

    assert!(verdict.is_none(), "a listening socket must never be condemned");
}

#[tokio::test]
async fn an_endpoint_with_nothing_listening_is_condemned() {
    // Bind then drop: the port is (almost certainly) free, so the connect is
    // refused rather than blackholed — same verdict, faster test.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let cfg = ss_ws_uplink(&format!("ws://127.0.0.1:{port}/ws"));

    let verdict =
        unreachable_uplink_endpoints(&DnsCache::default(), "test", &cfg, Duration::from_secs(2))
            .await;

    assert_eq!(verdict.as_deref(), Some(format!("127.0.0.1:{port}").as_str()));
}

#[tokio::test]
async fn one_live_endpoint_spares_the_uplink() {
    // All-or-nothing: a single dead fallback host stays the per-wire path's
    // problem, not grounds for condemning the whole uplink.
    let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live_port = live.local_addr().unwrap().port();
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    let mut cfg = ss_ws_uplink(&format!("ws://127.0.0.1:{live_port}/ws"));
    cfg.fallbacks = vec![ws_fallback(&format!("ws://127.0.0.1:{dead_port}/ws"))];

    let verdict =
        unreachable_uplink_endpoints(&DnsCache::default(), "test", &cfg, Duration::from_secs(2))
            .await;

    assert!(verdict.is_none());
}
