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
        transport: Some(UplinkTransport::Ss),
        tcp_ws_url: Some(Url::parse(url).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: Some(TransportMode::WsH1),
        udp_ws_url: Some(Url::parse(&(url.to_string() + "/udp")).unwrap()),
        udp_xhttp_url: None,
        udp_mode: Some(TransportMode::WsH1),
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: None,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        link: None,
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
        padding: None,
        shuffle_timer: None,
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
        tcp_xhttp_url: None,
        tcp_mode: None,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: None,
        vless_ws_url: None,
        vless_xhttp_url: Some(Url::parse(xhttp_url).unwrap()),
        vless_mode: Some(TransportMode::XhttpH1),
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        link: None,
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
        padding: None,
        shuffle_timer: None,
    }
}

fn empty_fallback() -> FallbackSection {
    FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: None,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: None,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: None,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
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

/// Resolve a single section AND run the per-group shuffle pass on
/// it. Mirrors the full `load_uplinks` pipeline for a one-uplink
/// configuration so the shuffle tests still exercise the real wire
/// permutation after `shuffle_wire_chains_per_group` was lifted out
/// of `TryFrom<ResolvedUplinkInput>` into the group-aware loader.
fn resolve_and_shuffle(section: UplinkSection) -> Result<UplinkConfig, anyhow::Error> {
    let group = section.group.clone();
    let cfg: UplinkConfig = ResolvedUplinkInput::from_section(0, &section).try_into()?;
    let mut buf = [cfg];
    super::super::uplinks::shuffle_wire_chains_per_group(&mut buf, &[group]);
    let [cfg] = buf;
    Ok(cfg)
}

// ── Happy paths ─────────────────────────────────────────────────────────────

#[test]
fn vless_primary_with_two_ws_fallbacks_inherits_password_and_fwmark() {
    let ws_fb = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://ws.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        udp_ws_url: Some(Url::parse("wss://ws.example.com/udp").unwrap()),
        udp_xhttp_url: None,
        tcp_mode: Some(TransportMode::WsH2),
        udp_mode: Some(TransportMode::WsH1),
        ..empty_fallback()
    };
    let ws_fb_2 = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://ws2.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let cfg = resolve(vless_uplink_section(
        "edge",
        "https://cdn.example.com/SECRET/xhttp",
        vec![ws_fb, ws_fb_2],
    ))
    .unwrap();

    assert_eq!(cfg.fallbacks.len(), 2);
    let ws = &cfg.fallbacks[0];
    assert_eq!(ws.transport, UplinkTransport::Ss);
    assert_eq!(ws.tcp_mode, TransportMode::WsH2);
    assert_eq!(ws.udp_mode, TransportMode::WsH1);
    assert_eq!(ws.password, "secret", "password inherited from parent");
    assert_eq!(ws.fwmark, Some(99), "fwmark inherited from parent");
    assert!(ws.ipv6_first, "ipv6_first inherited (parent set true)");
    assert!(ws.vless_id.is_none());

    let ws2 = &cfg.fallbacks[1];
    assert_eq!(ws2.transport, UplinkTransport::Ss);
    assert_eq!(ws2.password, "secret");
    assert_eq!(ws2.fwmark, Some(99));
}

#[test]
fn fallback_can_override_inherited_password_and_fwmark() {
    let fb = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        password: Some("override-secret".to_string()),
        fwmark: Some(7),
        ipv6_first: Some(false),
        ..empty_fallback()
    };
    let cfg =
        resolve(vless_uplink_section("edge", "https://cdn.example.com/SECRET/xhttp", vec![fb]))
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
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
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
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://a.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let ws_fb_2 = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://b.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
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
        transport: UplinkTransport::Ss,
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
fn rejects_vless_fallback_missing_vless_id() {
    let bad = FallbackSection {
        transport: UplinkTransport::Vless,
        vless_xhttp_url: Some(Url::parse("https://other.example.com/x").unwrap()),
        vless_mode: Some(TransportMode::XhttpH1),
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
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
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let fb_c = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-c.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
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
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let fb_c = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-c.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
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
        let cfg = resolve_and_shuffle(section).unwrap();
        assert!(cfg.shuffle_wires);
        // All four wires must still be Ws (transport unchanged for this
        // single-family setup) so the shuffle did not corrupt fields.
        assert_eq!(cfg.transport, UplinkTransport::Ss);
        for fb in &cfg.fallbacks {
            assert_eq!(fb.transport, UplinkTransport::Ss);
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
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
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
        let cfg = resolve_and_shuffle(section).unwrap();
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
    let cfg = resolve_and_shuffle(section).unwrap();
    assert!(cfg.shuffle_wires);
    assert!(cfg.fallbacks.is_empty());
    assert_eq!(cfg.tcp_ws_url.as_ref().unwrap().as_str(), "wss://primary.example.com/tcp");
}

#[test]
fn shuffle_keeps_combined_ss_fallback_dialable_when_promoted_to_primary() {
    // Repro of the dashboard "uplink aeza missing tcp dial URL" report.
    // Topology: a VLESS-XHTTP primary with a combined-path SS fallback
    // (`ss_xhttp_url` + `ss_mode`, no split `tcp_*`/`udp_*`). When
    // `shuffle_wires` promoted the SS wire into the primary slot the
    // primary<->fallback shape round-trip dropped the `ss_*` fields, so
    // `is_combined_ss()` turned false and `tcp_dial_url()` returned None —
    // but only on the restarts whose shuffle landed this wire at index 0,
    // which is why the chip came and went across restarts.
    let combined = FallbackSection {
        transport: UplinkTransport::Ss,
        ss_xhttp_url: Some(Url::parse("https://aeza.example.com/ssx").unwrap()),
        ss_mode: Some(TransportMode::XhttpH3),
        method: Some(CipherKind::Chacha20IetfPoly1305),
        password: Some("secret".to_string()),
        ..empty_fallback()
    };
    let combined_url = Url::parse("https://aeza.example.com/ssx").unwrap();

    let mut saw_ss_primary = false;
    for _ in 0..256 {
        let mut section =
            vless_uplink_section("aeza", "https://aeza.example.com/xhttp", vec![combined.clone()]);
        section.shuffle_wires = Some(true);
        let cfg = resolve_and_shuffle(section).unwrap();

        // Whichever wire landed at the primary slot: if it is the combined
        // SS one, it must still dial both legs through the shared URL.
        if cfg.transport == UplinkTransport::Ss {
            saw_ss_primary = true;
            assert!(cfg.is_combined_ss(), "promoted SS wire lost its combined marker");
            assert_eq!(cfg.tcp_dial_url(), Some(&combined_url), "promoted SS lost tcp dial URL");
            assert_eq!(cfg.udp_dial_url(), Some(&combined_url), "promoted SS lost udp dial URL");
        }
    }
    assert!(
        saw_ss_primary,
        "shuffle never promoted the combined SS wire to primary in 256 tries"
    );
}

#[test]
fn shuffle_keeps_combined_ss_primary_dialable_when_demoted_to_fallback() {
    // Symmetric guard: a combined-path SS *primary* must keep its `ss_*`
    // URL when `shuffle_wires` demotes it into the fallback list. The
    // primary->fallback shape extraction used to null the combined fields.
    let vless_fb = FallbackSection {
        transport: UplinkTransport::Vless,
        vless_ws_url: Some(Url::parse("wss://aeza.example.com/vless").unwrap()),
        vless_mode: Some(TransportMode::WsH3),
        vless_id: Some("d9ac06ee-c80b-4938-894b-328fff73222e".to_string()),
        ..empty_fallback()
    };
    let combined_url = Url::parse("https://aeza.example.com/ssx").unwrap();

    let mut saw_ss_demoted = false;
    for _ in 0..256 {
        let mut section =
            ss_xhttp_uplink_section("aeza", "https://aeza.example.com/ssx", TransportMode::XhttpH3);
        // Convert the split SS-XHTTP section into a combined one.
        section.tcp_xhttp_url = None;
        section.tcp_mode = None;
        section.ss_xhttp_url = Some(combined_url.clone());
        section.ss_mode = Some(TransportMode::XhttpH3);
        section.fallbacks = Some(vec![vless_fb.clone()]);
        section.shuffle_wires = Some(true);
        let cfg = resolve_and_shuffle(section).unwrap();

        if cfg.transport == UplinkTransport::Ss {
            // Combined SS stayed primary — still dials.
            assert!(cfg.is_combined_ss(), "combined SS primary lost its marker");
            assert_eq!(cfg.tcp_dial_url(), Some(&combined_url));
        } else {
            // Combined SS was demoted into the fallback list — must survive.
            saw_ss_demoted = true;
            let fb = cfg
                .fallbacks
                .iter()
                .find(|f| f.transport == UplinkTransport::Ss)
                .expect("combined SS wire vanished from the chain after demotion");
            assert!(fb.is_combined_ss(), "demoted SS wire lost its combined marker");
            assert_eq!(fb.tcp_dial_url(), Some(&combined_url), "demoted combined SS lost dial URL");
        }
    }
    assert!(saw_ss_demoted, "shuffle never demoted the combined SS primary in 256 tries");
}

#[test]
fn shuffle_wires_per_group_avoids_collisions_in_the_same_group() {
    // Three identical 3-wire uplinks in the same `main` group. Naive
    // independent shuffles would land on the same permutation ~17% of
    // the time per pair, so two of the three uplinks coincidentally
    // matching is ≈ 44% likely. The collision-free per-group pass
    // must do strictly better than that: with 6 distinct permutations
    // for 3 uplinks the loader can ALWAYS pick three distinct ones,
    // so the assertion is hard. We run it for many seeds to make
    // sure the dedup actually kicks in instead of relying on luck.
    let fb_a = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let make_section = |name: &str| {
        let mut s = ws_uplink_section(
            name,
            "wss://primary.example.com/tcp",
            vec![fb_a.clone(), fb_b.clone()],
        );
        s.group = Some("main".to_string());
        s.shuffle_wires = Some(true);
        s
    };

    for _ in 0..64 {
        let sections = [make_section("alpha"), make_section("beta"), make_section("gamma")];
        let group_labels: Vec<Option<String>> = sections.iter().map(|s| s.group.clone()).collect();
        let mut resolved: Vec<UplinkConfig> = sections
            .iter()
            .enumerate()
            .map(|(i, s)| ResolvedUplinkInput::from_section(i, s).try_into().unwrap())
            .collect();
        super::super::uplinks::shuffle_wire_chains_per_group(&mut resolved, &group_labels);

        let orderings: Vec<Vec<String>> = resolved
            .iter()
            .map(|u| {
                let mut v = vec![u.tcp_ws_url.as_ref().unwrap().as_str().to_string()];
                v.extend(
                    u.fallbacks
                        .iter()
                        .map(|fb| fb.tcp_ws_url.as_ref().unwrap().as_str().to_string()),
                );
                v
            })
            .collect();
        let unique: std::collections::HashSet<_> = orderings.iter().collect();
        assert_eq!(
            unique.len(),
            orderings.len(),
            "three 3-wire uplinks in the same group must end up with three distinct wire orderings (got {:?})",
            orderings,
        );
    }
}

#[test]
fn shuffle_wires_per_group_isolates_groups() {
    // Two uplinks in DIFFERENT groups must be allowed to coincidentally
    // share a permutation — the collision-free guarantee is per-group
    // and groups don't share state.
    let fb_a = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-a.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let fb_b = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://fb-b.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        ..empty_fallback()
    };
    let make_section = |name: &str, group: &str| {
        let mut s = ws_uplink_section(
            name,
            "wss://primary.example.com/tcp",
            vec![fb_a.clone(), fb_b.clone()],
        );
        s.group = Some(group.to_string());
        s.shuffle_wires = Some(true);
        s
    };
    // We can't directly observe "the loader does not consult the other
    // group's seen set" — assert it indirectly by checking that the
    // dedup state never bleeds into the second group's seen entry.
    // Concretely: run with one uplink per group and confirm both ran
    // through the shuffle without panicking (the seen-set lookup must
    // use the group key, not a single global one).
    let sections = [make_section("alpha", "group-a"), make_section("beta", "group-b")];
    let group_labels: Vec<Option<String>> = sections.iter().map(|s| s.group.clone()).collect();
    let mut resolved: Vec<UplinkConfig> = sections
        .iter()
        .enumerate()
        .map(|(i, s)| ResolvedUplinkInput::from_section(i, s).try_into().unwrap())
        .collect();
    super::super::uplinks::shuffle_wire_chains_per_group(&mut resolved, &group_labels);
    // No panic, both uplinks still have all three wires.
    for cfg in &resolved {
        assert_eq!(1 + cfg.fallbacks.len(), 3);
    }
}

// ── SS-over-XHTTP ─────────────────────────────────────────────────────────────

/// Build an SS uplink that dials over XHTTP: `tcp_mode = xhttp_*` with a
/// matching `tcp_xhttp_url` and no `tcp_ws_url`.
fn ss_xhttp_uplink_section(name: &str, xhttp_url: &str, mode: TransportMode) -> UplinkSection {
    UplinkSection {
        name: Some(name.to_string()),
        transport: Some(UplinkTransport::Ss),
        tcp_ws_url: None,
        tcp_xhttp_url: Some(Url::parse(xhttp_url).unwrap()),
        tcp_mode: Some(mode),
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: None,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: None,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        link: None,
        method: Some(CipherKind::Chacha20IetfPoly1305),
        password: Some("secret".to_string()),
        weight: Some(1.0),
        fwmark: None,
        ipv6_first: None,
        vless_id: None,
        group: None,
        fingerprint_profile: None,
        fallbacks: None,
        shuffle_wires: None,
        carrier_downgrade: None,
        padding: None,
        shuffle_timer: None,
    }
}

#[test]
fn ss_xhttp_primary_parses_and_dials_xhttp_url() {
    let cfg = resolve(ss_xhttp_uplink_section(
        "ss-xhttp",
        "https://cdn.example.com/ss",
        TransportMode::XhttpH2,
    ))
    .expect("ss-over-xhttp uplink should parse");
    assert_eq!(cfg.transport, UplinkTransport::Ss);
    assert_eq!(cfg.tcp_dial_mode(), TransportMode::XhttpH2);
    // The XHTTP mode must select `tcp_xhttp_url`, not `tcp_ws_url`.
    assert_eq!(cfg.tcp_dial_url().map(|u| u.as_str()), Some("https://cdn.example.com/ss"));
    assert!(cfg.tcp_ws_url.is_none());
}

#[test]
fn ss_xhttp_mode_requires_tcp_xhttp_url() {
    let mut section =
        ss_xhttp_uplink_section("ss-xhttp", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.tcp_xhttp_url = None;
    let err = resolve(section).expect_err("xhttp mode without tcp_xhttp_url must fail");
    assert!(err.to_string().contains("tcp_xhttp_url"), "unexpected error: {err}");
}

#[test]
fn ss_xhttp_mode_rejects_tcp_ws_url() {
    let mut section =
        ss_xhttp_uplink_section("ss-xhttp", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.tcp_ws_url = Some(Url::parse("wss://cdn.example.com/ws").unwrap());
    let err = resolve(section).expect_err("xhttp mode with tcp_ws_url must fail");
    assert!(err.to_string().contains("tcp_ws_url"), "unexpected error: {err}");
}

#[test]
fn ss_ws_mode_rejects_tcp_xhttp_url() {
    // A WS-family `tcp_mode` must not carry an XHTTP URL.
    let mut section = ws_uplink_section("ss-ws", "wss://cdn.example.com/ws", Vec::new());
    section.tcp_xhttp_url = Some(Url::parse("https://cdn.example.com/ss").unwrap());
    let err = resolve(section).expect_err("ws mode with tcp_xhttp_url must fail");
    assert!(err.to_string().contains("tcp_xhttp_url"), "unexpected error: {err}");
}

#[test]
fn ss_xhttp_fallback_after_ss_ws_primary_parses() {
    let xhttp_fb = FallbackSection {
        transport: UplinkTransport::Ss,
        tcp_xhttp_url: Some(Url::parse("https://cdn.example.com/ss").unwrap()),
        tcp_mode: Some(TransportMode::XhttpH2),
        ..empty_fallback()
    };
    let cfg = resolve(ws_uplink_section("ss", "wss://main.example.com/tcp", vec![xhttp_fb]))
        .expect("ss-ws primary with ss-xhttp fallback should parse");
    assert_eq!(cfg.fallbacks.len(), 1);
    let fb = &cfg.fallbacks[0];
    assert_eq!(fb.tcp_dial_mode(), TransportMode::XhttpH2);
    assert_eq!(fb.tcp_dial_url().map(|u| u.as_str()), Some("https://cdn.example.com/ss"));
}

#[test]
fn ss_udp_xhttp_parses_and_dials_udp_xhttp_url() {
    let mut section =
        ss_xhttp_uplink_section("ss-xhttp", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.udp_xhttp_url = Some(Url::parse("https://cdn.example.com/ss-udp").unwrap());
    section.udp_mode = Some(TransportMode::XhttpH2);
    let cfg = resolve(section).expect("ss-over-xhttp uplink with UDP should parse");
    assert_eq!(cfg.udp_dial_mode(), TransportMode::XhttpH2);
    assert_eq!(cfg.udp_dial_url().map(|u| u.as_str()), Some("https://cdn.example.com/ss-udp"));
    assert!(cfg.supports_udp(), "udp_xhttp_url should enable UDP");
}

#[test]
fn ss_udp_xhttp_mode_rejects_udp_ws_url() {
    let mut section =
        ss_xhttp_uplink_section("ss-xhttp", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.udp_mode = Some(TransportMode::XhttpH2);
    section.udp_ws_url = Some(Url::parse("wss://cdn.example.com/udp").unwrap());
    let err = resolve(section).expect_err("udp xhttp mode with udp_ws_url must fail");
    assert!(err.to_string().contains("udp_ws_url"), "unexpected error: {err}");
}

#[test]
fn combined_ss_xhttp_url_dials_one_url_for_both_legs() {
    // Combined XHTTP: no split tcp_*/udp_*, just ss_xhttp_url + ss_mode.
    let mut section =
        ss_xhttp_uplink_section("combined", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.tcp_xhttp_url = None;
    section.tcp_mode = None;
    section.ss_xhttp_url = Some(Url::parse("https://cdn.example.com/ssc").unwrap());
    section.ss_mode = Some(TransportMode::XhttpH2);
    let cfg = resolve(section).expect("combined ss_xhttp_url should resolve");
    assert!(cfg.is_combined_ss(), "ss_xhttp_url should mark the uplink combined");
    let expected = Url::parse("https://cdn.example.com/ssc").unwrap();
    assert_eq!(cfg.tcp_dial_url(), Some(&expected), "tcp leg dials the combined URL");
    assert_eq!(cfg.udp_dial_url(), Some(&expected), "udp leg dials the same combined URL");
    assert_eq!(cfg.tcp_dial_mode(), TransportMode::XhttpH2);
    assert_eq!(cfg.udp_dial_mode(), TransportMode::XhttpH2);
}

#[test]
fn combined_ss_ws_url_uses_ws_carrier() {
    let mut section = ss_xhttp_uplink_section(
        "combined-ws",
        "https://cdn.example.com/ss",
        TransportMode::XhttpH2,
    );
    section.tcp_xhttp_url = None;
    section.tcp_mode = None;
    section.ss_ws_url = Some(Url::parse("wss://cdn.example.com/ws").unwrap());
    section.ss_mode = Some(TransportMode::WsH2);
    let cfg = resolve(section).expect("combined ss_ws_url should resolve");
    assert!(cfg.is_combined_ss());
    let expected = Url::parse("wss://cdn.example.com/ws").unwrap();
    assert_eq!(cfg.tcp_dial_url(), Some(&expected));
    assert_eq!(cfg.udp_dial_url(), Some(&expected));
}

#[test]
fn combined_ss_xhttp_url_requires_xhttp_ss_mode() {
    let mut section =
        ss_xhttp_uplink_section("bad", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.tcp_xhttp_url = None;
    section.tcp_mode = None;
    section.ss_xhttp_url = Some(Url::parse("https://cdn.example.com/ssc").unwrap());
    section.ss_mode = Some(TransportMode::WsH2); // WS mode for an XHTTP URL
    let err = resolve(section).expect_err("carrier mismatch must fail");
    assert!(err.to_string().contains("requires an XHTTP"), "unexpected error: {err}");
}

#[test]
fn combined_ss_url_rejects_split_url_fields() {
    // ss_xhttp_url + a leftover tcp_xhttp_url → mutual-exclusion error.
    let mut section =
        ss_xhttp_uplink_section("bad", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.ss_xhttp_url = Some(Url::parse("https://cdn.example.com/combined").unwrap());
    section.ss_mode = Some(TransportMode::XhttpH2);
    let err = resolve(section).expect_err("split + combined must fail");
    assert!(
        err.to_string().contains("mutually exclusive with the split"),
        "unexpected error: {err}"
    );
}

#[test]
fn combined_ss_fallback_does_not_require_tcp_ws_url() {
    // Repro of the production bug: a combined SS fallback (`ss_ws_url` +
    // `ss_mode`) was validated as a split wire and wrongly demanded
    // `tcp_ws_url`. It must resolve to a combined wire instead.
    let fb = FallbackSection {
        transport: UplinkTransport::Ss,
        ss_ws_url: Some(Url::parse("wss://fb.example.com/ws").unwrap()),
        ss_mode: Some(TransportMode::WsH3),
        ..empty_fallback()
    };
    let mut section =
        ss_xhttp_uplink_section("p", "https://cdn.example.com/ss", TransportMode::XhttpH2);
    section.fallbacks = Some(vec![fb]);
    let cfg = resolve(section).expect("combined ss fallback should resolve");
    let wire = &cfg.fallbacks[0];
    assert!(wire.is_combined_ss(), "fallback should be combined");
    let expected = Url::parse("wss://fb.example.com/ws").unwrap();
    assert_eq!(wire.tcp_dial_url(), Some(&expected));
    assert_eq!(wire.udp_dial_url(), Some(&expected));
    assert_eq!(wire.tcp_dial_mode(), TransportMode::WsH3);
}

#[test]
fn combined_ss_xhttp_fallback_resolves() {
    // Same on the XHTTP carrier: `ss_xhttp_url` + an XHTTP `ss_mode`.
    let fb = FallbackSection {
        transport: UplinkTransport::Ss,
        ss_xhttp_url: Some(Url::parse("https://fb.example.com/xh").unwrap()),
        ss_mode: Some(TransportMode::XhttpH3),
        ..empty_fallback()
    };
    let mut section = ws_uplink_section("p", "wss://cdn.example.com/ws", Vec::new());
    section.fallbacks = Some(vec![fb]);
    let cfg = resolve(section).expect("combined ss-xhttp fallback should resolve");
    let wire = &cfg.fallbacks[0];
    assert!(wire.is_combined_ss());
    let expected = Url::parse("https://fb.example.com/xh").unwrap();
    assert_eq!(wire.tcp_dial_url(), Some(&expected));
    assert_eq!(wire.tcp_dial_mode(), TransportMode::XhttpH3);
}

// ── SS share-link (`link = "ss://…"`) ─────────────────────────────────────────

// base64url of "chacha20-ietf-poly1305:secret" (SIP002 userinfo).
const SS_USERINFO: &str = "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ";

/// An uplink section carrying nothing but a share-link `link` field, mirroring
/// the minimal `[[outline.uplinks]] link = "…"` shape.
fn link_only_section(name: &str, link: &str) -> UplinkSection {
    let mut section = ws_uplink_section(name, "wss://placeholder.example.com/ws", Vec::new());
    section.transport = None;
    section.tcp_ws_url = None;
    section.tcp_mode = None;
    section.udp_ws_url = None;
    section.udp_mode = None;
    section.method = None;
    section.password = None;
    section.link = Some(link.to_string());
    section
}

#[test]
fn ss_share_link_expands_into_combined_ws_uplink() {
    let cfg = resolve(link_only_section(
        "ss-share",
        &format!(
            "ss://{SS_USERINFO}@ss.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fss&alpn=h2#edge"
        ),
    ))
    .expect("ss share link should resolve");

    assert_eq!(cfg.transport, UplinkTransport::Ss);
    assert!(cfg.is_combined_ss());
    assert_eq!(cfg.cipher, CipherKind::Chacha20IetfPoly1305);
    assert_eq!(cfg.password, "secret");
    assert_eq!(cfg.ss_mode, Some(TransportMode::WsH2));
    let expected = Url::parse("wss://ss.example.com:443/secret/ss").unwrap();
    assert_eq!(cfg.tcp_dial_url(), Some(&expected));
    assert_eq!(cfg.udp_dial_url(), Some(&expected));
    assert_eq!(cfg.tcp_dial_mode(), TransportMode::WsH2);
}

#[test]
fn ss_share_link_xhttp_targets_ss_xhttp_url() {
    let cfg = resolve(link_only_section(
        "ss-share-xhttp",
        &format!("ss://{SS_USERINFO}@ss.example.com:443?type=xhttp&security=tls&path=%2Fxhttp"),
    ))
    .expect("ss xhttp share link should resolve");

    assert_eq!(cfg.transport, UplinkTransport::Ss);
    assert!(cfg.is_combined_ss());
    assert_eq!(cfg.ss_mode, Some(TransportMode::XhttpH2));
    let expected = Url::parse("https://ss.example.com:443/xhttp").unwrap();
    assert_eq!(cfg.tcp_dial_url(), Some(&expected));
}

#[test]
fn ss_share_link_rejects_explicit_credentials() {
    let mut section = link_only_section(
        "ss-share",
        &format!("ss://{SS_USERINFO}@ss.example.com:443?type=ws&security=tls"),
    );
    section.password = Some("override".to_string());
    let err = resolve(section).expect_err("explicit password must conflict with ss:// link");
    assert!(format!("{err:#}").contains("password"));
}

#[test]
fn ss_share_link_rejects_transport_vless() {
    let mut section = link_only_section(
        "ss-share",
        &format!("ss://{SS_USERINFO}@ss.example.com:443?type=ws&security=tls"),
    );
    section.transport = Some(UplinkTransport::Vless);
    let err = resolve(section).expect_err("ss:// link with transport=vless must error");
    assert!(format!("{err:#}").contains("transport=ss"));
}
