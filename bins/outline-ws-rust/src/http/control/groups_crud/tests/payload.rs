use toml_edit::Table;

use super::payload::{GroupPayload, merge_patch_into_table, payload_to_table, table_to_section};
use crate::http::control::config_edit::render_table_with_arrays;

fn payload(json: &str) -> GroupPayload {
    serde_json::from_str(json).expect("valid payload")
}

#[test]
fn payload_round_trips_through_group_section() {
    let p = payload(
        r#"{"name":"main","mode":"active_active","routing_scope":"per_flow","warm_standby_tcp":1}"#,
    );
    let table = payload_to_table(&p).expect("to table");
    let text = render_table_with_arrays(&table);
    // The exact shape the group validator will re-parse.
    let _section = table_to_section(&table).expect("parses as UplinkGroupSection");
    assert!(text.contains("mode = \"active_active\""), "got: {text}");
    assert!(text.contains("warm_standby_tcp = 1"), "got: {text}");
}

#[test]
fn deny_unknown_fields_rejects_typos() {
    let err = serde_json::from_str::<GroupPayload>(r#"{"moode":"active_active"}"#).unwrap_err();
    assert!(err.to_string().contains("unknown field"), "got: {err}");
}

#[test]
fn probe_sub_table_round_trips() {
    let p = payload(r#"{"name":"g","probe":{"interval_secs":60}}"#);
    let text = render_table_with_arrays(&payload_to_table(&p).expect("to table"));
    assert!(text.contains("[probe]"), "got: {text}");
    assert!(text.contains("interval_secs = 60"), "got: {text}");
    table_to_section(&payload_to_table(&p).expect("to table")).expect("probe parses");
}

#[test]
fn merge_patch_replaces_fields_and_ignores_name() {
    // existing table has mode + name; patch flips mode and (illegally) name.
    let mut existing: Table =
        payload_to_table(&payload(r#"{"name":"main","mode":"active_active"}"#)).expect("to table");
    merge_patch_into_table(
        &mut existing,
        &payload(r#"{"name":"renamed","mode":"active_passive"}"#),
    )
    .expect("merge ok");
    let text = render_table_with_arrays(&existing);
    assert!(text.contains("mode = \"active_passive\""), "mode replaced: {text}");
    // name is identity — merge must leave the original on disk.
    assert!(text.contains("name = \"main\""), "name unchanged: {text}");
    assert!(!text.contains("renamed"), "name not overwritten: {text}");
}
