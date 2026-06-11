use toml_edit::{DocumentMut, Item, Value};

use crate::config::validate_uplink_section;

use super::mutate::{
    count_uplinks_in_group, find_group_mut, find_outline_uplink_index, get_or_init_outline_uplinks,
};
use super::payload::{FallbackPayload, MutationResponse, UplinkPayload};
use super::payload::{merge_patch_into_table, payload_to_section, payload_to_table, table_to_json};

fn sample_config() -> &'static str {
    r#"# Test config
[[uplink_group]]
name = "core"

[[outline.uplinks]]
name = "u1"
group = "core"
transport = "shadowsocks"
tcp_addr = "1.2.3.4:8388"
method = "chacha20-ietf-poly1305"
password = "secret-password-1"

[[outline.uplinks]]
name = "u2"
group = "core"
transport = "shadowsocks"
tcp_addr = "5.6.7.8:8388"
method = "chacha20-ietf-poly1305"
password = "secret-password-2"
"#
}

#[test]
fn finds_group_by_name() {
    let mut doc = sample_config().parse::<DocumentMut>().unwrap();
    assert!(find_group_mut(&mut doc, "core").is_some());
    assert!(find_group_mut(&mut doc, "missing").is_none());
}

#[test]
fn finds_uplink_index_by_group_and_name() {
    let mut doc = sample_config().parse::<DocumentMut>().unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    assert_eq!(find_outline_uplink_index(arr, "core", "u1"), Some(0));
    assert_eq!(find_outline_uplink_index(arr, "core", "u2"), Some(1));
    assert_eq!(find_outline_uplink_index(arr, "core", "u3"), None);
    // Wrong group must not match even when the name exists.
    assert_eq!(find_outline_uplink_index(arr, "other", "u1"), None);
}

#[test]
fn insert_appends_uplink_table() {
    let mut doc = sample_config().parse::<DocumentMut>().unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let payload = UplinkPayload {
        name: Some("u3".into()),
        transport: Some("shadowsocks".into()),
        tcp_addr: Some("9.9.9.9:8388".into()),
        method: Some("chacha20-ietf-poly1305".into()),
        password: Some("secret-password-3".into()),
        ..Default::default()
    };
    let mut tbl = payload_to_table(&payload);
    tbl.insert("group", Item::Value(Value::from("core")));
    arr.push(tbl);
    let rendered = doc.to_string();
    assert!(rendered.contains("\"u3\""), "missing inserted uplink:\n{rendered}");
    assert!(rendered.contains("9.9.9.9:8388"));
    assert!(rendered.contains("group = \"core\""));
}

#[test]
fn merge_patch_updates_existing_fields_only() {
    let mut doc = sample_config().parse::<DocumentMut>().unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "u1").unwrap();
    let patch = UplinkPayload {
        password: Some("new-password".into()),
        weight: Some(2.5),
        ..Default::default()
    };
    merge_patch_into_table(arr.get_mut(idx).unwrap(), &patch);
    let rendered = doc.to_string();
    assert!(rendered.contains("new-password"));
    assert!(rendered.contains("2.5"));
    // Unmodified field survives.
    assert!(rendered.contains("1.2.3.4:8388"));
}

#[test]
fn remove_drops_entry() {
    let mut doc = sample_config().parse::<DocumentMut>().unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "u1").unwrap();
    arr.remove(idx);
    let rendered = doc.to_string();
    assert!(!rendered.contains("\"u1\""));
    assert!(rendered.contains("\"u2\""));
}

#[test]
fn count_uplinks_in_group_counts_only_matching_group() {
    let mut doc = sample_config().parse::<DocumentMut>().unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    assert_eq!(count_uplinks_in_group(arr, "core"), 2);
    assert_eq!(count_uplinks_in_group(arr, "missing"), 0);
}

#[test]
fn enrich_round_trip_returns_uplink_fields() {
    let mut doc = sample_config().parse::<DocumentMut>().unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "u1").unwrap();
    let json = table_to_json(arr.get(idx).unwrap()).expect("table_to_json");
    assert_eq!(json["name"], "u1");
    assert_eq!(json["group"], "core");
    assert_eq!(json["tcp_addr"], "1.2.3.4:8388");
}

#[test]
fn payload_round_trip_validates_as_section() {
    let payload = UplinkPayload {
        name: Some("u9".into()),
        transport: Some("shadowsocks".into()),
        tcp_addr: Some("1.1.1.1:8388".into()),
        method: Some("chacha20-ietf-poly1305".into()),
        password: Some("some-long-password".into()),
        ..Default::default()
    };
    let section = payload_to_section(&payload, Some("core")).unwrap();
    assert_eq!(section.name.as_deref(), Some("u9"));
    validate_uplink_section(&section, 0).unwrap();
}

#[test]
fn mutation_response_reports_apply_or_restart_activation_path() {
    let with_apply =
        serde_json::to_value(MutationResponse::staged("core".into(), "u1".into(), "updated", true))
            .unwrap();
    assert_eq!(with_apply["apply_required"], true);
    assert_eq!(with_apply["restart_required"], false);

    let without_apply = serde_json::to_value(MutationResponse::staged(
        "core".into(),
        "u1".into(),
        "updated",
        false,
    ))
    .unwrap();
    assert_eq!(without_apply["apply_required"], false);
    assert_eq!(without_apply["restart_required"], true);
}

#[test]
fn vless_xhttp_payload_round_trips_through_table() {
    // Regression: the CRUD payload originally lacked `vless_xhttp_url`,
    // so editing or creating an XHTTP-mode uplink through the dashboard
    // 400'd with `unknown field` (UplinkPayload uses
    // `deny_unknown_fields`). The full triple — vless_xhttp_url +
    // vless_mode + vless_id — must survive payload → toml table → toml
    // section without loss.
    let payload = UplinkPayload {
        name: Some("vx".into()),
        transport: Some("vless".into()),
        vless_xhttp_url: Some("https://example.com/SECRET/xhttp".into()),
        vless_mode: Some("xhttp_h3".into()),
        vless_id: Some("11111111-2222-3333-4444-555555555555".into()),
        ..Default::default()
    };
    let tbl = payload_to_table(&payload);
    let rendered = tbl.to_string();
    assert!(rendered.contains("vless_xhttp_url"), "field missing:\n{rendered}");
    assert!(rendered.contains("xhttp_h3"));
    let section = payload_to_section(&payload, Some("core")).unwrap();
    assert!(section.vless_xhttp_url.is_some());
    validate_uplink_section(&section, 0).unwrap();
}

#[test]
fn merge_patch_updates_vless_xhttp_url() {
    let mut doc = r#"
[[uplink_group]]
name = "core"

[[outline.uplinks]]
name = "vx"
group = "core"
transport = "vless"
vless_xhttp_url = "https://old.example.com/A/xhttp"
vless_mode = "xhttp_h2"
vless_id = "11111111-2222-3333-4444-555555555555"
"#
    .parse::<DocumentMut>()
    .unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "vx").unwrap();
    let patch = UplinkPayload {
        vless_xhttp_url: Some("https://new.example.com/B/xhttp".into()),
        vless_mode: Some("xhttp_h3".into()),
        ..Default::default()
    };
    merge_patch_into_table(arr.get_mut(idx).unwrap(), &patch);
    let rendered = doc.to_string();
    assert!(rendered.contains("https://new.example.com/B/xhttp"));
    assert!(rendered.contains("xhttp_h3"));
    assert!(!rendered.contains("https://old.example.com/A/xhttp"));
}

#[test]
fn vless_share_link_payload_round_trips_through_validation() {
    // Operators can paste a `vless://` URI into the dashboard form instead
    // of filling in `vless_id` / `vless_*_url` / `vless_mode` by hand. The
    // payload must survive the table round-trip and validate via the same
    // pipeline the loader uses at startup.
    let payload = UplinkPayload {
        name: Some("share".into()),
        transport: Some("vless".into()),
        link: Some(
            "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443\
             ?type=ws&security=tls&path=%2Fsecret%2Fvless&alpn=h3#share"
                .into(),
        ),
        ..Default::default()
    };
    let tbl = payload_to_table(&payload);
    let rendered = tbl.to_string();
    assert!(rendered.contains("link ="), "share-link missing in TOML:\n{rendered}");
    let section = payload_to_section(&payload, Some("core")).unwrap();
    validate_uplink_section(&section, 0).unwrap();
}

#[test]
fn validation_rejects_link_alongside_explicit_vless_fields() {
    let payload = UplinkPayload {
        name: Some("conflict".into()),
        transport: Some("vless".into()),
        link: Some(
            "vless://11111111-2222-3333-4444-555555555555@host:443?type=ws&security=tls".into(),
        ),
        vless_id: Some("11111111-2222-3333-4444-555555555555".into()),
        ..Default::default()
    };
    let section = payload_to_section(&payload, Some("core")).unwrap();
    let err = validate_uplink_section(&section, 0).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("mutually exclusive"),
        "expected conflict error, got: {message}"
    );
}

#[test]
fn validation_rejects_missing_password_for_shadowsocks() {
    let payload = UplinkPayload {
        name: Some("u9".into()),
        transport: Some("shadowsocks".into()),
        tcp_addr: Some("1.1.1.1:8388".into()),
        method: Some("chacha20-ietf-poly1305".into()),
        // password intentionally missing
        ..Default::default()
    };
    let section = payload_to_section(&payload, Some("core")).unwrap();
    assert!(validate_uplink_section(&section, 0).is_err());
}

// ── Fallbacks via CRUD ──────────────────────────────────────────────────────

#[test]
fn payload_with_fallbacks_round_trips_through_section() {
    let payload = UplinkPayload {
        name: Some("edge".into()),
        transport: Some("vless".into()),
        vless_xhttp_url: Some("https://cdn.example.com/SECRET/xhttp".into()),
        vless_mode: Some("xhttp_h3".into()),
        vless_id: Some("00000000-0000-0000-0000-000000000000".into()),
        method: Some("chacha20-ietf-poly1305".into()),
        password: Some("some-long-password".into()),
        fallbacks: Some(vec![
            FallbackPayload {
                transport: "ws".into(),
                tcp_ws_url: Some("wss://ws.example.com/tcp".into()),
                tcp_mode: Some("ws_h2".into()),
                udp_ws_url: Some("wss://ws.example.com/udp".into()),
                udp_mode: Some("ws_h1".into()),
                ..Default::default()
            },
            FallbackPayload {
                transport: "shadowsocks".into(),
                tcp_addr: Some("1.2.3.4:8388".into()),
                udp_addr: Some("1.2.3.4:8389".into()),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };
    let section = payload_to_section(&payload, Some("core")).unwrap();
    let fbs = section.fallbacks.as_ref().expect("fallbacks must round-trip");
    assert_eq!(fbs.len(), 2);
    assert_eq!(format!("{:?}", fbs[0].transport), "Ws");
    assert_eq!(fbs[0].tcp_ws_url.as_ref().unwrap().as_str(), "wss://ws.example.com/tcp");
    assert_eq!(format!("{:?}", fbs[1].transport), "Shadowsocks");
    // Validation walks the same pipeline as the TOML loader.
    validate_uplink_section(&section, 0).unwrap();
}

#[test]
fn rendered_toml_inserted_into_document_includes_fallbacks_array() {
    // `Table::to_string()` doesn't render nested ArrayOfTables without a
    // surrounding document context (the array needs the parent's path to
    // generate `[[parent.fallbacks]]` headers). We verify the array shape
    // by inserting our payload-built table into a real document — the
    // same path the create handler uses.
    let payload = UplinkPayload {
        name: Some("edge".into()),
        transport: Some("vless".into()),
        vless_ws_url: Some("wss://primary.example.com/v".into()),
        vless_mode: Some("ws_h2".into()),
        vless_id: Some("00000000-0000-0000-0000-000000000000".into()),
        fallbacks: Some(vec![FallbackPayload {
            transport: "ws".into(),
            tcp_ws_url: Some("wss://ws.example.com/tcp".into()),
            tcp_mode: Some("ws_h1".into()),
            ..Default::default()
        }]),
        ..Default::default()
    };
    let mut doc = r#"
[[uplink_group]]
name = "core"
"#
    .parse::<DocumentMut>()
    .unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    arr.push(payload_to_table(&payload));
    let rendered = doc.to_string();
    assert!(
        rendered.contains("[[outline.uplinks.fallbacks]]"),
        "rendered TOML must contain fallbacks array-of-tables:\n{rendered}",
    );
    assert!(rendered.contains("transport = \"ws\""));
    assert!(rendered.contains("tcp_ws_url = \"wss://ws.example.com/tcp\""));
}

#[test]
fn patch_replaces_fallbacks_when_present() {
    let mut doc = r#"
[[uplink_group]]
name = "core"

[[outline.uplinks]]
name = "edge"
group = "core"
transport = "vless"
vless_ws_url = "wss://primary.example.com/v"
vless_mode = "ws_h2"
vless_id = "00000000-0000-0000-0000-000000000000"
method = "chacha20-ietf-poly1305"
password = "some-long-password"

[[outline.uplinks.fallbacks]]
transport = "shadowsocks"
tcp_addr = "old.example.com:8388"
"#
    .parse::<DocumentMut>()
    .unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "edge").unwrap();
    let tbl = arr.get_mut(idx).unwrap();
    let patch = UplinkPayload {
        fallbacks: Some(vec![FallbackPayload {
            transport: "ws".into(),
            tcp_ws_url: Some("wss://newws.example.com/tcp".into()),
            tcp_mode: Some("ws_h1".into()),
            ..Default::default()
        }]),
        ..Default::default()
    };
    merge_patch_into_table(tbl, &patch);
    // Render the full document — `Table::to_string()` doesn't surface
    // nested ArrayOfTables without a parent path, so we ask the
    // document (which knows the path) to render the patched state.
    let rendered = doc.to_string();
    assert!(rendered.contains("wss://newws.example.com/tcp"));
    assert!(
        !rendered.contains("old.example.com"),
        "patch must replace the existing fallbacks list:\n{rendered}",
    );
}

#[test]
fn empty_patch_array_clears_fallbacks() {
    let mut doc = r#"
[[uplink_group]]
name = "core"

[[outline.uplinks]]
name = "edge"
group = "core"
transport = "vless"
vless_ws_url = "wss://primary.example.com/v"
vless_mode = "ws_h2"
vless_id = "00000000-0000-0000-0000-000000000000"
method = "chacha20-ietf-poly1305"
password = "some-long-password"

[[outline.uplinks.fallbacks]]
transport = "shadowsocks"
tcp_addr = "old.example.com:8388"
"#
    .parse::<DocumentMut>()
    .unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "edge").unwrap();
    let tbl = arr.get_mut(idx).unwrap();
    let patch = UplinkPayload {
        fallbacks: Some(Vec::new()),
        ..Default::default()
    };
    merge_patch_into_table(tbl, &patch);
    let rendered = tbl.to_string();
    assert!(
        !rendered.contains("fallbacks"),
        "empty array in patch must clear all fallbacks:\n{rendered}",
    );
}

#[test]
fn omitting_fallbacks_in_patch_preserves_existing() {
    let mut doc = r#"
[[uplink_group]]
name = "core"

[[outline.uplinks]]
name = "edge"
group = "core"
transport = "vless"
vless_ws_url = "wss://primary.example.com/v"
vless_mode = "ws_h2"
vless_id = "00000000-0000-0000-0000-000000000000"
method = "chacha20-ietf-poly1305"
password = "some-long-password"

[[outline.uplinks.fallbacks]]
transport = "shadowsocks"
tcp_addr = "kept.example.com:8388"
"#
    .parse::<DocumentMut>()
    .unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "edge").unwrap();
    let tbl = arr.get_mut(idx).unwrap();
    // Patch touches an unrelated field; fallbacks left out (None).
    let patch = UplinkPayload {
        password: Some("new-password".into()),
        ..Default::default()
    };
    merge_patch_into_table(tbl, &patch);
    let rendered = doc.to_string();
    assert!(rendered.contains("password = \"new-password\""));
    assert!(
        rendered.contains("kept.example.com"),
        "fallbacks must survive a patch that doesn't mention them:\n{rendered}",
    );
}

#[test]
fn payload_accepts_vless_xhttp_primary_with_vless_ws_fallback() {
    // The validator no longer rejects same-transport fallbacks: the most
    // common shape is a VLESS-XHTTP primary that wants a VLESS-WS
    // fallback (same `transport = "vless"`, different carrier family).
    // This test pins that the CRUD pipeline accepts the configuration
    // end-to-end and produces an UplinkConfig with the fallback wired.
    let payload = UplinkPayload {
        name: Some("edge".into()),
        transport: Some("vless".into()),
        vless_xhttp_url: Some("https://cdn.example.com/SECRET/xhttp".into()),
        vless_mode: Some("xhttp_h3".into()),
        vless_id: Some("00000000-0000-0000-0000-000000000000".into()),
        method: Some("chacha20-ietf-poly1305".into()),
        password: Some("some-long-password".into()),
        fallbacks: Some(vec![FallbackPayload {
            transport: "vless".into(),
            vless_ws_url: Some("wss://vless-ws.example.com/v".into()),
            vless_mode: Some("ws_h3".into()),
            vless_id: Some("11111111-2222-3333-4444-555555555555".into()),
            ..Default::default()
        }]),
        ..Default::default()
    };
    let section = payload_to_section(&payload, Some("core")).unwrap();
    let cfg = validate_uplink_section(&section, 0).unwrap();
    assert_eq!(cfg.fallbacks.len(), 1);
    assert!(matches!(cfg.fallbacks[0].transport, outline_uplink::UplinkTransport::Vless));
    // Different carrier family from primary's xhttp_h3.
    assert!(matches!(cfg.fallbacks[0].vless_mode, outline_uplink::TransportMode::WsH3));
}
