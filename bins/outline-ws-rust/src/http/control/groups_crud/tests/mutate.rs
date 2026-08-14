use toml_edit::DocumentMut;

use super::super::payload::GroupPayload;
use super::{
    apply_create, apply_delete, apply_reorder, apply_update, count_uplinks_for_group,
    get_or_init_uplink_groups,
};

const BASE: &str = "\
[[uplink_group]]
name = \"main\"
mode = \"active_active\"

[[outline.uplinks]]
name = \"cloud1\"
group = \"main\"
transport = \"ss\"
";

fn doc() -> DocumentMut {
    BASE.parse::<DocumentMut>().unwrap()
}

fn payload(json: &str) -> GroupPayload {
    serde_json::from_str(json).unwrap()
}

#[test]
fn create_appends_group_to_rendered_doc() {
    let mut d = doc();
    apply_create(
        &mut d,
        &payload(r#"{"name":"backup","mode":"active_passive","routing_scope":"global"}"#),
    )
    .expect("create ok");
    let text = d.to_string();
    // Assert the RENDERED document, not just Vec state (position-no-op guard).
    assert!(text.contains("name = \"backup\""), "backup group rendered: {text}");
    assert!(text.contains("mode = \"active_passive\""), "policy rendered: {text}");
    assert!(text.contains("name = \"main\""), "existing group preserved: {text}");
}

#[test]
fn create_rejects_duplicate_name() {
    let mut d = doc();
    let err = apply_create(&mut d, &payload(r#"{"name":"main","mode":"active_active"}"#))
        .expect_err("duplicate");
    assert!(err.contains("already exists"), "got: {err}");
}

#[test]
fn create_rejects_reserved_name() {
    let mut d = doc();
    let err = apply_create(&mut d, &payload(r#"{"name":"direct","mode":"active_active"}"#))
        .expect_err("reserved");
    assert!(err.contains("reserved"), "got: {err}");
}

#[test]
fn update_merges_policy_in_place() {
    let mut d = doc();
    apply_update(&mut d, "main", &payload(r#"{"routing_scope":"per_uplink"}"#)).expect("update ok");
    let text = d.to_string();
    assert!(text.contains("routing_scope = \"per_uplink\""), "new field rendered: {text}");
    assert!(text.contains("mode = \"active_active\""), "untouched field preserved: {text}");
}

#[test]
fn update_unknown_group_is_not_found() {
    let mut d = doc();
    let err = apply_update(&mut d, "ghost", &payload(r#"{"mode":"active_passive"}"#))
        .expect_err("missing");
    assert!(err.contains("not found"), "got: {err}");
}

#[test]
fn delete_nonempty_group_is_refused() {
    let mut d = doc();
    // "main" still owns uplink "cloud1".
    assert_eq!(count_uplinks_for_group(&d, "main"), 1);
    let err = apply_delete(&mut d, "main").expect_err("has uplinks");
    assert!(err.contains("uplink"), "got: {err}");
}

#[test]
fn delete_empty_group_removes_it_from_rendered_doc() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"name":"backup","mode":"active_passive"}"#)).expect("create");
    apply_delete(&mut d, "backup").expect("delete empty");
    let text = d.to_string();
    assert!(!text.contains("backup"), "backup gone from render: {text}");
    assert!(text.contains("name = \"main\""), "main preserved: {text}");
}

#[test]
fn update_rejects_invalid_policy() {
    let mut d = doc();
    // reselect requires active_passive; on an active_active group it must fail.
    let err = apply_update(&mut d, "main", &payload(r#"{"reselect_interval":"10h"}"#))
        .expect_err("reselect needs active_passive");
    assert!(!err.is_empty(), "got empty error");
}

#[test]
fn reorder_moves_group_and_renders_new_order() {
    let mut d = "[[uplink_group]]\nname = \"a\"\nmode = \"active_active\"\n\n\
                 [[uplink_group]]\nname = \"b\"\nmode = \"active_active\"\n\n\
                 [[uplink_group]]\nname = \"c\"\nmode = \"active_active\"\n"
        .parse::<DocumentMut>()
        .unwrap();
    {
        let arr = get_or_init_uplink_groups(&mut d);
        apply_reorder(arr, "c", 0).expect("reorder ok");
    }
    let text = d.to_string();
    // Assert the RENDERED order (positions reassigned), not just Vec order:
    // "c" must now precede "a", which precedes "b". Guards the position-no-op.
    let ia = text.find("name = \"a\"").expect("a present");
    let ib = text.find("name = \"b\"").expect("b present");
    let ic = text.find("name = \"c\"").expect("c present");
    assert!(ic < ia && ia < ib, "expected c,a,b order in render: {text}");
}

#[test]
fn reorder_target_out_of_range_is_rejected() {
    let mut d = doc();
    let arr = get_or_init_uplink_groups(&mut d);
    let err = apply_reorder(arr, "main", 5).expect_err("out of range");
    assert!(err.contains("out of range"), "got: {err}");
}
