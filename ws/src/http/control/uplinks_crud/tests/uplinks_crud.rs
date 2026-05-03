use toml_edit::{DocumentMut, Item, Value};

use crate::config::validate_uplink_section;

use super::UplinkPayload;
use super::mutate::{
    count_uplinks_in_group, find_group_mut, find_outline_uplink_index, get_or_init_outline_uplinks,
};
use super::payload::{
    merge_patch_into_table, payload_to_section, payload_to_table, table_to_json,
};

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
            "vless://11111111-2222-3333-4444-555555555555@host:443?type=ws&security=tls"
                .into(),
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
