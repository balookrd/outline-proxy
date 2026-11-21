use toml_edit::ArrayOfTables;

use super::{RoutePayload, payload_to_table, route_revision};
use crate::config::RouteSection;
use crate::http::control::config_edit::render_table_with_arrays;

fn payload(json: &str) -> RoutePayload {
    serde_json::from_str(json).expect("valid payload")
}

#[test]
fn payload_round_trips_through_route_section() {
    let p =
        payload(r#"{"prefixes":["10.0.0.0/8","192.168.0.0/16"],"via":"direct","invert":false}"#);
    let table = payload_to_table(&p);
    let text = render_table_with_arrays(&table);
    // The exact shape the whole-list validator will re-parse.
    let section: RouteSection = toml::from_str(&text).expect("parses as RouteSection");
    let _ = section; // fields are pub(super); reaching here proves the round-trip.
    assert!(text.contains("via = \"direct\""), "got: {text}");
    assert!(text.contains("10.0.0.0/8"), "got: {text}");
}

#[test]
fn default_rule_serializes_without_matchers() {
    let p = payload(r#"{"default":true,"via":"main"}"#);
    let text = render_table_with_arrays(&payload_to_table(&p));
    assert!(text.contains("default = true"));
    assert!(!text.contains("prefixes"));
}

#[test]
fn deny_unknown_fields_rejects_typos() {
    let err = serde_json::from_str::<RoutePayload>(r#"{"viaa":"main"}"#).unwrap_err();
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

#[test]
fn revision_is_stable_and_content_sensitive() {
    let mut arr = ArrayOfTables::new();
    arr.push(payload_to_table(&payload(r#"{"default":true,"via":"main"}"#)));
    let r1 = route_revision(&arr);
    let r2 = route_revision(&arr);
    assert_eq!(r1, r2, "same content → same revision");

    arr.push(payload_to_table(&payload(r#"{"prefixes":["10.0.0.0/8"],"via":"direct"}"#)));
    assert_ne!(r1, route_revision(&arr), "changed content → changed revision");
}
