//! Tests for the per-uplink fallback validation pipeline:
//! `UplinkSection (TOML) → ResolvedUplinkInput → UplinkConfig`.
//!
//! These pin the validation contract: required wire fields per fallback
//! transport, transport-disjoint field gating, parent-inheritance for
//! `cipher` / `password` / `fwmark` / `ipv6_first` / `fingerprint_profile`,
//! and the per-list "primary ≠ fallback transport, no duplicate fallback
//! transport" rules.

use shadowsocks_crypto::CipherKind;
use url::Url;

use outline_uplink::{TransportMode, UplinkConfig, UplinkTransport};

use super::super::super::schema::{FallbackSection, UplinkSection};
use super::super::uplinks::ResolvedUplinkInput;

fn ws_uplink_section(name: &str, url: &str, fallbacks: Vec<FallbackSection>) -> UplinkSection {
    UplinkSection {
        name: Some(name.to_string()),
        transport: Some(UplinkTransport::Ws),
        tcp_ws_url: Some(Url::parse(url).unwrap()),
        tcp_mode: Some(TransportMode::WsH1),
        udp_ws_url: Some(Url::parse(&(url.to_string() + "/udp")).unwrap()),
        udp_mode: Some(TransportMode::WsH1),
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: None,
        link: None,
        tcp_addr: None,
        udp_addr: None,
        method: Some(CipherKind::Chacha20IetfPoly1305),
        password: Some("secret".to_string()),
        weight: Some(1.0),
        fwmark: None,
        ipv6_first: None,
        vless_id: None,
        group: None,
        fingerprint_profile: None,
        fallbacks: if fallbacks.is_empty() { None } else { Some(fallbacks) },
    }
}

fn vless_uplink_section(
    name: &str,
    xhttp_url: &str,
    fallbacks: Vec<FallbackSection>,
) -> UplinkSection {
    UplinkSection {
        name: Some(name.to_string()),
        transport: Some(UplinkTransport::Vless),
        tcp_ws_url: None,
        tcp_mode: None,
        udp_ws_url: None,
        udp_mode: None,
        vless_ws_url: None,
        vless_xhttp_url: Some(Url::parse(xhttp_url).unwrap()),
        vless_mode: Some(TransportMode::XhttpH1),
        link: None,
        tcp_addr: None,
        udp_addr: None,
        method: Some(CipherKind::Chacha20IetfPoly1305),
        password: Some("secret".to_string()),
        weight: Some(1.0),
        fwmark: Some(99),
        ipv6_first: Some(true),
        vless_id: Some("00000000-0000-0000-0000-000000000000".to_string()),
        group: None,
        fingerprint_profile: None,
        fallbacks: if fallbacks.is_empty() { None } else { Some(fallbacks) },
    }
}

fn empty_fallback() -> FallbackSection {
    FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: None,
        tcp_mode: None,
        udp_ws_url: None,
        udp_mode: None,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: None,
        tcp_addr: None,
        udp_addr: None,
        method: None,
        password: None,
        fwmark: None,
        ipv6_first: None,
        vless_id: None,
        fingerprint_profile: None,
    }
}

fn resolve(section: UplinkSection) -> Result<UplinkConfig, anyhow::Error> {
    ResolvedUplinkInput::from_section(0, &section).try_into()
}

// ── Happy paths ─────────────────────────────────────────────────────────────

#[test]
fn ws_primary_with_ss_fallback_inherits_cipher_and_password() {
    let ss_fb = FallbackSection {
        transport: UplinkTransport::Shadowsocks,
        tcp_addr: Some("1.2.3.4:8388".parse().unwrap()),
        udp_addr: Some("1.2.3.4:8389".parse().unwrap()),
        ..empty_fallback()
    };
    let cfg =
        resolve(ws_uplink_section("edge", "wss://primary.example.com/tcp", vec![ss_fb])).unwrap();

    assert_eq!(cfg.fallbacks.len(), 1);
    let fb = &cfg.fallbacks[0];
    assert_eq!(fb.transport, UplinkTransport::Shadowsocks);
    assert!(
        matches!(fb.cipher, CipherKind::Chacha20IetfPoly1305),
        "cipher inherits from parent"
    );
    assert_eq!(fb.password, "secret", "password inherits from parent");
    assert_eq!(fb.fwmark, None, "parent's None fwmark inherited as None");
    assert!(!fb.ipv6_first, "parent's false ipv6_first inherited");
    assert_eq!(fb.tcp_addr.as_ref().unwrap().to_string(), "1.2.3.4:8388");
    assert_eq!(fb.udp_addr.as_ref().unwrap().to_string(), "1.2.3.4:8389");
    assert!(fb.tcp_ws_url.is_none(), "WS fields nulled for SS fallback");
    assert!(fb.vless_id.is_none());
}

#[test]
fn vless_primary_with_ws_and_ss_fallbacks_inherits_password_and_fwmark() {
    let ws_fb = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://ws.example.com/tcp").unwrap()),
        udp_ws_url: Some(Url::parse("wss://ws.example.com/udp").unwrap()),
        tcp_mode: Some(TransportMode::WsH2),
        udp_mode: Some(TransportMode::WsH1),
        ..empty_fallback()
    };
    let ss_fb = FallbackSection {
        transport: UplinkTransport::Shadowsocks,
        tcp_addr: Some("9.9.9.9:443".parse().unwrap()),
        udp_addr: Some("9.9.9.9:443".parse().unwrap()),
        ..empty_fallback()
    };
    let cfg = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![ws_fb, ss_fb],
    ))
    .unwrap();

    assert_eq!(cfg.fallbacks.len(), 2);
    let ws = &cfg.fallbacks[0];
    assert_eq!(ws.transport, UplinkTransport::Ws);
    assert_eq!(ws.tcp_mode, TransportMode::WsH2);
    assert_eq!(ws.udp_mode, TransportMode::WsH1);
    assert_eq!(ws.password, "secret", "password inherited from parent");
    assert_eq!(ws.fwmark, Some(99), "fwmark inherited from parent");
    assert!(ws.ipv6_first, "ipv6_first inherited (parent set true)");
    assert!(ws.vless_id.is_none());

    let ss = &cfg.fallbacks[1];
    assert_eq!(ss.transport, UplinkTransport::Shadowsocks);
    assert_eq!(ss.password, "secret");
    assert_eq!(ss.fwmark, Some(99));
}

#[test]
fn fallback_can_override_inherited_password_and_fwmark() {
    let ss_fb = FallbackSection {
        transport: UplinkTransport::Shadowsocks,
        tcp_addr: Some("9.9.9.9:443".parse().unwrap()),
        password: Some("override-secret".to_string()),
        fwmark: Some(7),
        ipv6_first: Some(false),
        ..empty_fallback()
    };
    let cfg = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![ss_fb],
    ))
    .unwrap();

    let fb = &cfg.fallbacks[0];
    assert_eq!(fb.password, "override-secret");
    assert_eq!(fb.fwmark, Some(7));
    assert!(!fb.ipv6_first);
}

// ── Error paths ─────────────────────────────────────────────────────────────

#[test]
fn rejects_fallback_with_same_transport_as_parent() {
    let ws_fb = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://other.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let err = resolve(ws_uplink_section("edge", "wss://primary.example.com/tcp", vec![ws_fb]))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("matches the parent uplink's primary transport"),
        "got: {err}"
    );
}

#[test]
fn rejects_duplicate_fallback_transport() {
    let ws_fb_1 = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://a.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let ws_fb_2 = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://b.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let err = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![ws_fb_1, ws_fb_2],
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("a second time"), "got: {err}");
}

#[test]
fn rejects_ws_fallback_missing_tcp_ws_url() {
    let bad = FallbackSection {
        transport: UplinkTransport::Ws,
        // tcp_ws_url omitted — required
        ..empty_fallback()
    };
    let err = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![bad],
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires `tcp_ws_url`"), "got: {err}");
}

#[test]
fn rejects_shadowsocks_fallback_missing_tcp_addr() {
    let bad = FallbackSection {
        transport: UplinkTransport::Shadowsocks,
        // tcp_addr omitted — required
        ..empty_fallback()
    };
    let err = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![bad],
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("requires `tcp_addr`"), "got: {err}");
}

#[test]
fn rejects_vless_fallback_missing_vless_id() {
    let bad = FallbackSection {
        transport: UplinkTransport::Vless,
        vless_xhttp_url: Some(Url::parse("https://other.example.com/x").unwrap()),
        vless_mode: Some(TransportMode::XhttpH1),
        // vless_id omitted — required and not inherited
        ..empty_fallback()
    };
    let err = resolve(ws_uplink_section("edge", "wss://primary.example.com/tcp", vec![bad]))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("requires `vless_id`") && err.contains("not inherited"),
        "got: {err}"
    );
}

#[test]
fn rejects_ws_fallback_with_cross_family_fields() {
    let bad = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://other.example.com/tcp").unwrap()),
        // SS-only field on a WS fallback — should be rejected.
        tcp_addr: Some("1.2.3.4:8388".parse().unwrap()),
        ..empty_fallback()
    };
    let err = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![bad],
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("must not set `tcp_addr`/`udp_addr`"), "got: {err}");
}

#[test]
fn rejects_shadowsocks_fallback_with_websocket_fields() {
    let bad = FallbackSection {
        transport: UplinkTransport::Shadowsocks,
        tcp_addr: Some("1.2.3.4:8388".parse().unwrap()),
        // WS-only field on an SS fallback — should be rejected.
        tcp_ws_url: Some(Url::parse("wss://other.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let err = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![bad],
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("must not"), "got: {err}");
    assert!(err.contains("websocket fields"), "got: {err}");
}

#[test]
fn no_fallbacks_yields_empty_list() {
    let cfg = resolve(ws_uplink_section("edge", "wss://primary.example.com/tcp", vec![])).unwrap();
    assert!(cfg.fallbacks.is_empty());
}
