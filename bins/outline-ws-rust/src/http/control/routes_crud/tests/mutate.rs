use std::path::Path;

use toml_edit::DocumentMut;

use super::super::payload::RoutePayload;
use super::{
    apply_create, apply_delete, apply_reorder, apply_update, group_names_in_doc,
    validate_route_array,
};

const BASE: &str = "\
[[uplink_group]]
name = \"main\"

[[route]]
prefixes = [\"10.0.0.0/8\"]
via = \"direct\"

[[route]]
default = true
via = \"main\"
";

fn doc() -> DocumentMut {
    BASE.parse::<DocumentMut>().unwrap()
}

fn payload(json: &str) -> RoutePayload {
    serde_json::from_str(json).unwrap()
}

#[test]
fn create_inserts_before_default_by_default() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"domains":["ads.example"],"via":"drop"}"#), None)
        .expect("create ok");
    let arr = d.get("route").unwrap().as_array_of_tables().unwrap();
    assert_eq!(arr.len(), 3);
    // New rule sits at index 1, default stays last.
    assert_eq!(arr.get(1).unwrap().get("via").unwrap().as_str(), Some("drop"));
    assert!(arr.get(2).unwrap().get("default").unwrap().as_bool().unwrap());
}

#[test]
fn delete_default_is_refused() {
    let mut d = doc();
    let err = apply_delete(&mut d, 1).expect_err("default index");
    assert!(err.contains("default"), "got: {err}");
}

#[test]
fn update_clears_default_is_refused() {
    let mut d = doc();
    // Index 1 is the default rule; a payload without `default` would clear it.
    let err = apply_update(&mut d, 1, &payload(r#"{"via":"main"}"#)).expect_err("clearing default");
    assert!(err.contains("default"), "got: {err}");
}

#[test]
fn update_adds_matcher_to_default_is_refused() {
    let mut d = doc();
    let err = apply_update(
        &mut d,
        1,
        &payload(r#"{"default":true,"via":"main","prefixes":["1.2.3.0/24"]}"#),
    )
    .expect_err("matcher on default");
    assert!(err.contains("matcher"), "got: {err}");
}

#[test]
fn reorder_moves_rule() {
    let mut d = doc();
    // BASE order: [0] = direct (prefixes 10.0.0.0/8), [1] = default (main).
    // Move the default rule to the front.
    apply_reorder(&mut d, 1, 0).expect("reorder ok");
    let arr = d.get("route").unwrap().as_array_of_tables().unwrap();
    // Vec order changed: default now at index 0.
    assert!(arr.get(0).unwrap().get("default").unwrap().as_bool().unwrap(), "vec order");
    // The RENDERED output must reflect the move too. toml_edit sorts
    // `[[route]]` tables by each table's stored `position` (source order) on
    // encode, so a reorder that only touches the Vec (leaving positions
    // untouched) is a silent no-op on disk and in `route_revision`. This
    // asserts the real, rendered order — the property the production bug broke.
    let rendered = d.to_string();
    let default_at = rendered.find("default = true").expect("default present");
    let direct_at = rendered.find("10.0.0.0/8").expect("direct present");
    assert!(
        default_at < direct_at,
        "rendered order must reflect the reorder (default before direct):\n{rendered}"
    );
}

/// Sanity check for the happy path: the BASE doc's existing rules (a valid
/// CIDR routed `direct`, plus the mandatory default) must pass whole-list
/// validation, proving the `RoutingTable::compile` step added alongside this
/// validator doesn't over-reject configs that were always valid.
#[tokio::test]
async fn validate_accepts_a_valid_config() {
    let d = doc();
    let groups = group_names_in_doc(&d);
    let names: Vec<&str> = groups.iter().map(String::as_str).collect();
    validate_route_array(&d, &names, Path::new("/tmp"))
        .await
        .expect("base doc is valid");
}

#[tokio::test]
async fn validate_rejects_via_to_unknown_group() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"prefixes":["1.2.3.0/24"],"via":"ghost"}"#), Some(0))
        .expect("staged");
    let groups = group_names_in_doc(&d);
    let names: Vec<&str> = groups.iter().map(String::as_str).collect();
    let err = validate_route_array(&d, &names, Path::new("/tmp"))
        .await
        .expect_err("bad via");
    assert!(
        format!("{err:#}").contains("ghost") || format!("{err:#}").contains("group"),
        "got: {err:#}"
    );
}

/// `load_routing_config` alone only checks structure (has prefixes, `via`
/// resolves) — it never parses a CIDR string. This rule is structurally
/// valid (non-empty `prefixes`, `via = "direct"` needs no group at all), so
/// only `RoutingTable::compile` — run inside `validate_route_array` since the
/// boot-safety fix — catches the unparseable prefix. Guards against the CRUD
/// endpoint staging a rule that passes validation but panics/errors
/// `RoutingTable::compile` at the next boot.
#[tokio::test]
async fn validate_rejects_route_that_fails_to_compile() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"prefixes":["garbage"],"via":"direct"}"#), Some(0))
        .expect("staged");
    let groups = group_names_in_doc(&d);
    let names: Vec<&str> = groups.iter().map(String::as_str).collect();
    let err = validate_route_array(&d, &names, Path::new("/tmp"))
        .await
        .expect_err("garbage prefix must not validate");
    assert!(
        format!("{err:#}").contains("garbage") || format!("{err:#}").contains("invalid IP"),
        "got: {err:#}"
    );
}

#[test]
fn group_names_are_extracted() {
    assert_eq!(group_names_in_doc(&doc()), vec!["main".to_string()]);
}
