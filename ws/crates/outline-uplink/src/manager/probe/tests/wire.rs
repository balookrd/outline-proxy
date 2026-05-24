//! Unit tests for the per-wire probe helpers.
//!
//! The end-to-end fallback-wire probe loop talks to a real network, so the
//! tests here cover the pure pieces: wire-view materialisation and the
//! "which wire is the probe target" decision. Integration with the probe
//! machinery is exercised by the existing snapshot tests in
//! `tests/fallback.rs` plus manual verification.

use super::target_wire_for_fallback_probe;

use crate::config::{CipherKind, FallbackTransport, TransportMode, UplinkConfig, UplinkTransport};

fn vless_xhttp_primary() -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: Some(url::Url::parse("https://cdn.example.com/SECRET/xhttp").unwrap()),
        vless_mode: TransportMode::XhttpH3,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: Some([0u8; 16]),
        fingerprint_profile: None,
        fallbacks: Vec::new(),
    }
}

fn ws_fallback() -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(url::Url::parse("wss://ws.example.com/tcp").unwrap()),
        tcp_mode: TransportMode::WsH2,
        udp_ws_url: Some(url::Url::parse("wss://ws.example.com/udp").unwrap()),
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        vless_id: None,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "shared".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

fn ss_fallback() -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Shadowsocks,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        vless_id: None,
        tcp_addr: Some("9.9.9.9:8388".parse().unwrap()),
        udp_addr: Some("9.9.9.9:8388".parse().unwrap()),
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "shared".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

#[test]
fn wire_view_index_zero_returns_primary_with_empty_fallbacks() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), ss_fallback()];

    let view = cfg.wire_view(0).expect("primary view exists");
    assert_eq!(view.transport, UplinkTransport::Vless);
    assert_eq!(view.vless_mode, TransportMode::XhttpH3);
    assert!(
        view.fallbacks.is_empty(),
        "wire view must not carry the parent's fallbacks (probe code path treats it as a single wire)",
    );
    assert_eq!(view.name, "edge");
}

#[test]
fn wire_view_first_fallback_is_synthetic_uplink_with_fallback_fields() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), ss_fallback()];

    let view = cfg.wire_view(1).expect("first fallback view exists");
    assert_eq!(view.transport, UplinkTransport::Ws);
    assert_eq!(view.tcp_mode, TransportMode::WsH2);
    assert_eq!(view.tcp_ws_url.as_ref().unwrap().as_str(), "wss://ws.example.com/tcp",);
    assert!(view.fallbacks.is_empty());
    // Identity fields inherited from parent for log/metric attribution.
    assert_eq!(view.name, "edge");
    assert_eq!(view.weight, 1.0);
}

#[test]
fn wire_view_second_fallback_walks_chain() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), ss_fallback()];

    let view = cfg.wire_view(2).expect("second fallback view exists");
    assert_eq!(view.transport, UplinkTransport::Shadowsocks);
    assert_eq!(view.tcp_addr.as_ref().unwrap().to_string(), "9.9.9.9:8388");
}

#[test]
fn wire_view_out_of_range_is_none() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback()];
    assert!(cfg.wire_view(2).is_none());
}

#[test]
fn target_wire_picks_first_fallback_when_active_still_on_primary() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback()];
    // Both transports report active_wire = 0 (failure streak hasn't crossed
    // min_failures yet) — bootstrap path: still probe wire 1 so the failing
    // primary's first cycle gets its fallback validated immediately.
    assert_eq!(target_wire_for_fallback_probe(&cfg, 0, 0), Some(1));
}

#[test]
fn target_wire_follows_active_wire_when_advanced() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), ss_fallback()];
    // TCP has flipped to wire 2, UDP still on wire 1 — probe whichever is
    // furthest along, so we validate the wire that any new TCP session
    // would actually land on.
    assert_eq!(target_wire_for_fallback_probe(&cfg, 2, 1), Some(2));
}

#[test]
fn target_wire_none_when_no_fallbacks() {
    let cfg = vless_xhttp_primary();
    assert!(target_wire_for_fallback_probe(&cfg, 0, 0).is_none());
}

#[test]
fn target_wire_none_when_active_index_overflows_chain() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback()];
    // Defensive: a stale active_wire value past the configured chain
    // length must not cause a panic from `wire_view`. Returns None so the
    // caller silently skips this cycle and lets the next reload settle.
    assert!(target_wire_for_fallback_probe(&cfg, 5, 0).is_none());
}
