//! Pure data-shape tests for `FallbackTransport` helpers and
//! `UplinkConfig::supports_udp_any`.
//!
//! Dial-loop integration is exercised end-to-end at the proxy crate
//! layer (where the network primitives live); these tests pin the
//! public-API contract on the fallback runtime types so downstream
//! callers can rely on it without spinning up sockets.

use url::Url;

use crate::config::{
    CipherKind, FallbackTransport, TransportMode, UplinkConfig, UplinkTransport,
};

fn vless_xhttp_primary() -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: Some(Url::parse("https://cdn.example.com/SECRET/xhttp").unwrap()),
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

/// Shadowsocks primary configured WITHOUT a UDP address — actually
/// `supports_udp() == false`. Used by the `supports_udp_any` tests
/// to verify that a UDP-capable fallback re-enables UDP candidacy.
fn ss_tcp_only_primary() -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Shadowsocks,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: Some("1.2.3.4:8388".parse().unwrap()),
        udp_addr: None, // <-- no UDP on primary
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
    }
}

fn ws_fallback(udp: bool) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://ws.example.com/tcp").unwrap()),
        tcp_mode: TransportMode::WsH2,
        udp_ws_url: if udp {
            Some(Url::parse("wss://ws.example.com/udp").unwrap())
        } else {
            None
        },
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        vless_id: None,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

fn ss_fallback(udp: bool) -> FallbackTransport {
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
        tcp_addr: Some("1.2.3.4:8388".parse().unwrap()),
        udp_addr: if udp { Some("1.2.3.4:8389".parse().unwrap()) } else { None },
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

#[test]
fn ws_fallback_dial_url_picks_tcp_url_for_tcp() {
    let fb = ws_fallback(true);
    let url = fb.tcp_dial_url().unwrap();
    assert_eq!(url.as_str(), "wss://ws.example.com/tcp");
    assert_eq!(fb.tcp_dial_mode(), TransportMode::WsH2);
}

#[test]
fn ws_fallback_dial_url_picks_udp_url_for_udp() {
    let fb = ws_fallback(true);
    let url = fb.udp_dial_url().unwrap();
    assert_eq!(url.as_str(), "wss://ws.example.com/udp");
    assert_eq!(fb.udp_dial_mode(), TransportMode::WsH1);
}

#[test]
fn ws_fallback_supports_udp_only_when_udp_url_set() {
    assert!(ws_fallback(true).supports_udp());
    assert!(!ws_fallback(false).supports_udp());
}

#[test]
fn ss_fallback_no_dial_url_but_supports_udp_via_addr() {
    let fb = ss_fallback(true);
    assert!(fb.tcp_dial_url().is_none(), "SS fallback has no WS URL");
    assert!(fb.udp_dial_url().is_none());
    assert!(fb.supports_udp(), "SS fallback supports UDP via udp_addr");
    assert!(!ss_fallback(false).supports_udp());
}

#[test]
fn vless_fallback_xhttp_mode_uses_xhttp_url() {
    let fb = FallbackTransport {
        transport: UplinkTransport::Vless,
        vless_xhttp_url: Some(Url::parse("https://cdn.example.com/x").unwrap()),
        vless_ws_url: Some(Url::parse("wss://other.example.com/ws").unwrap()),
        vless_mode: TransportMode::XhttpH2,
        vless_id: Some([1u8; 16]),
        ..ws_fallback(false)
    };
    let url = fb.tcp_dial_url().unwrap();
    assert_eq!(url.as_str(), "https://cdn.example.com/x");
    let url = fb.udp_dial_url().unwrap();
    assert_eq!(url.as_str(), "https://cdn.example.com/x");
}

#[test]
fn vless_fallback_ws_mode_uses_ws_url() {
    let fb = FallbackTransport {
        transport: UplinkTransport::Vless,
        vless_xhttp_url: Some(Url::parse("https://cdn.example.com/x").unwrap()),
        vless_ws_url: Some(Url::parse("wss://other.example.com/ws").unwrap()),
        vless_mode: TransportMode::WsH2,
        vless_id: Some([1u8; 16]),
        ..ws_fallback(false)
    };
    let url = fb.tcp_dial_url().unwrap();
    assert_eq!(url.as_str(), "wss://other.example.com/ws");
}

// ── supports_udp_any ─────────────────────────────────────────────────────────

#[test]
fn supports_udp_any_returns_true_when_primary_supports_udp() {
    let mut cfg = vless_xhttp_primary();
    // VLESS-XHTTP TCP-style only (XHTTP doesn't carry UDP) — mark as ws-mode
    // so primary supports UDP via the same URL.
    cfg.vless_mode = TransportMode::WsH2;
    cfg.vless_ws_url = Some(Url::parse("wss://primary.example.com/ws").unwrap());
    cfg.vless_xhttp_url = None;
    assert!(cfg.supports_udp(), "primary supports UDP via vless_ws_url");
    assert!(cfg.supports_udp_any());
}

#[test]
fn supports_udp_any_returns_true_when_only_fallback_supports_udp() {
    // SS primary with no `udp_addr` is the canonical TCP-only primary
    // (VLESS-XHTTP and VLESS-WS both flip `supports_udp` true via the
    // shared dial URL because mux.cool tunnels UDP through the same
    // session).
    let primary_supports_udp = ss_tcp_only_primary().supports_udp();
    assert!(!primary_supports_udp, "SS primary without udp_addr is TCP-only");

    let mut cfg = ss_tcp_only_primary();
    cfg.fallbacks = vec![ws_fallback(true)]; // UDP-capable fallback
    assert!(!cfg.supports_udp(), "primary alone still doesn't carry UDP");
    assert!(
        cfg.supports_udp_any(),
        "fallback's UDP capability surfaces through supports_udp_any"
    );
}

#[test]
fn supports_udp_any_false_when_neither_primary_nor_fallback_supports_udp() {
    let mut cfg = ss_tcp_only_primary();
    cfg.fallbacks = vec![ws_fallback(false)]; // TCP-only fallback
    assert!(!cfg.supports_udp());
    assert!(
        !cfg.supports_udp_any(),
        "all wires are TCP-only, supports_udp_any is false"
    );
}

#[test]
fn supports_udp_any_unaffected_when_primary_already_supports_udp() {
    let mut cfg = vless_xhttp_primary();
    cfg.vless_mode = TransportMode::WsH2;
    cfg.vless_ws_url = Some(Url::parse("wss://primary.example.com/ws").unwrap());
    cfg.vless_xhttp_url = None;
    cfg.fallbacks = vec![ss_fallback(false)]; // TCP-only fallback
    assert!(cfg.supports_udp());
    assert!(
        cfg.supports_udp_any(),
        "primary's UDP support already satisfies supports_udp_any"
    );
}
