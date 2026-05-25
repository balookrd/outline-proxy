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
        shuffle_wires: None,
        carrier_downgrade: None,
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
        shuffle_wires: None,
        carrier_downgrade: None,
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

// ── Same-transport-as-parent fallbacks are now allowed ─────────────────────
//
// The validator no longer rejects fallbacks whose `transport` matches the
// parent's primary. The motivating use case is a VLESS primary on
// `xhttp_h*` that wants to fall back to a *different VLESS endpoint* on
// `ws_h*` — same `transport = "vless"`, different carrier family. The dial
// loop and per-wire mode tracking treat each fallback as its own wire
// regardless of `transport`, so the relaxation is safe; uniqueness of
// identity is now the operator's responsibility.

#[test]
fn allows_vless_xhttp_primary_with_vless_ws_fallback() {
    let ws_fb = FallbackSection {
        transport: UplinkTransport::Vless,
        vless_ws_url: Some(Url::parse("wss://vless-ws.example.com/v").unwrap()),
        vless_mode: Some(TransportMode::WsH3),
        vless_id: Some("11111111-2222-3333-4444-555555555555".into()),
        ..empty_fallback()
    };
    let cfg = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![ws_fb],
    ))
    .unwrap();
    assert_eq!(cfg.fallbacks.len(), 1);
    assert_eq!(cfg.fallbacks[0].transport, UplinkTransport::Vless);
    assert_eq!(cfg.fallbacks[0].vless_mode, TransportMode::WsH3);
    // Distinct dial URL from primary's xhttp endpoint.
    assert_eq!(
        cfg.fallbacks[0].vless_ws_url.as_ref().unwrap().as_str(),
        "wss://vless-ws.example.com/v",
    );
}

#[test]
fn allows_two_ws_fallbacks_at_distinct_endpoints() {
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
    let cfg = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![ws_fb_1, ws_fb_2],
    ))
    .unwrap();
    assert_eq!(cfg.fallbacks.len(), 2);
    assert_eq!(cfg.fallbacks[0].tcp_ws_url.as_ref().unwrap().host_str(), Some("a.example.com"));
    assert_eq!(cfg.fallbacks[1].tcp_ws_url.as_ref().unwrap().host_str(), Some("b.example.com"));
}

#[test]
fn rejects_ws_fallback_missing_tcp_ws_url() {
    let bad = FallbackSection {
        transport: UplinkTransport::Ws,
        // tcp_ws_url omitted — required
        ..empty_fallback()
    };
    let err =
        resolve(vless_uplink_section("edge", "https://cdn.example.com/SECRET/xhttp", vec![bad]))
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
    let err =
        resolve(vless_uplink_section("edge", "https://cdn.example.com/SECRET/xhttp", vec![bad]))
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
    let err =
        resolve(vless_uplink_section("edge", "https://cdn.example.com/SECRET/xhttp", vec![bad]))
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
    let err =
        resolve(vless_uplink_section("edge", "https://cdn.example.com/SECRET/xhttp", vec![bad]))
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

// ── shuffle_wires ──────────────────────────────────────────────────────────

#[test]
fn shuffle_wires_defaults_to_false_when_unset() {
    let cfg = resolve(ws_uplink_section("edge", "wss://primary.example.com/tcp", vec![])).unwrap();
    assert!(!cfg.shuffle_wires);
}

#[test]
fn shuffle_wires_off_preserves_operator_ordering() {
    // Three distinct WS fallback URLs let us assert ordering after resolve.
    let fb_a = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let fb_c = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-c.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let mut section =
        ws_uplink_section("edge", "wss://primary.example.com/tcp", vec![fb_a, fb_b, fb_c]);
    section.shuffle_wires = Some(false);
    let cfg = resolve(section).unwrap();
    assert!(!cfg.shuffle_wires);
    assert_eq!(cfg.tcp_ws_url.as_ref().unwrap().as_str(), "wss://primary.example.com/tcp");
    let fb_urls: Vec<_> = cfg
        .fallbacks
        .iter()
        .map(|f| f.tcp_ws_url.as_ref().unwrap().as_str().to_string())
        .collect();
    assert_eq!(
        fb_urls,
        vec![
            "wss://fb-a.example.com/tcp",
            "wss://fb-b.example.com/tcp",
            "wss://fb-c.example.com/tcp",
        ]
    );
}

#[test]
fn shuffle_wires_on_keeps_full_wire_set_intact() {
    // The shuffle must not drop, duplicate, or corrupt wires — we resolve
    // many times and assert the multi-set of dial URLs is always the same
    // four URLs (primary + 3 fallbacks). This guards the conversion path
    // (primary ↔ FallbackTransport) without being flaky on the specific
    // ordering, which is intentionally random.
    let fb_a = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let fb_c = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-c.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let expected: std::collections::BTreeSet<String> = [
        "wss://primary.example.com/tcp",
        "wss://fb-a.example.com/tcp",
        "wss://fb-b.example.com/tcp",
        "wss://fb-c.example.com/tcp",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    for _ in 0..32 {
        let mut section = ws_uplink_section(
            "edge",
            "wss://primary.example.com/tcp",
            vec![fb_a.clone(), fb_b.clone(), fb_c.clone()],
        );
        section.shuffle_wires = Some(true);
        let cfg = resolve(section).unwrap();
        assert!(cfg.shuffle_wires);
        // All four wires must still be Ws (transport unchanged for this
        // single-family setup) so the shuffle did not corrupt fields.
        assert_eq!(cfg.transport, UplinkTransport::Ws);
        for fb in &cfg.fallbacks {
            assert_eq!(fb.transport, UplinkTransport::Ws);
        }
        let mut wires: std::collections::BTreeSet<String> = cfg
            .fallbacks
            .iter()
            .map(|f| f.tcp_ws_url.as_ref().unwrap().as_str().to_string())
            .collect();
        wires.insert(cfg.tcp_ws_url.as_ref().unwrap().as_str().to_string());
        assert_eq!(wires, expected, "shuffle must preserve the wire set exactly");
    }
}

#[test]
fn shuffle_wires_on_eventually_promotes_a_fallback_to_primary() {
    // Probabilistic guard against a "shuffle that always lands primary at 0"
    // bug: with 3 wires and 64 attempts, the probability of NEVER seeing
    // primary moved off slot 0 is (1/3)^64 ≈ 3.4e-31 — negligible.
    let fb_a = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        ..empty_fallback()
    };

    let mut saw_primary_displaced = false;
    for _ in 0..64 {
        let mut section = ws_uplink_section(
            "edge",
            "wss://primary.example.com/tcp",
            vec![fb_a.clone(), fb_b.clone()],
        );
        section.shuffle_wires = Some(true);
        let cfg = resolve(section).unwrap();
        if cfg.tcp_ws_url.as_ref().unwrap().as_str() != "wss://primary.example.com/tcp" {
            saw_primary_displaced = true;
            break;
        }
    }
    assert!(
        saw_primary_displaced,
        "shuffle_wires=true never moved primary off slot 0 in 64 attempts"
    );
}

#[test]
fn shuffle_wires_on_with_no_fallbacks_is_a_no_op() {
    let mut section = ws_uplink_section("edge", "wss://primary.example.com/tcp", vec![]);
    section.shuffle_wires = Some(true);
    let cfg = resolve(section).unwrap();
    assert!(cfg.shuffle_wires);
    assert!(cfg.fallbacks.is_empty());
    assert_eq!(cfg.tcp_ws_url.as_ref().unwrap().as_str(), "wss://primary.example.com/tcp");
}
