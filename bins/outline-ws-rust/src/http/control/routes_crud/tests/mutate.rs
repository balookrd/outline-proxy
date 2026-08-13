use std::path::Path;

use toml_edit::DocumentMut;

use super::super::payload::RoutePayload;
use super::{apply_create, apply_delete, apply_reorder, group_names_in_doc, validate_route_array};

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
fn reorder_moves_rule() {
    let mut d = doc();
    apply_reorder(&mut d, 0, 1).expect("reorder ok");
    let arr = d.get("route").unwrap().as_array_of_tables().unwrap();
    // default moved to front, direct rule to index 1.
    assert!(arr.get(0).unwrap().get("default").unwrap().as_bool().unwrap());
}

#[test]
fn validate_rejects_via_to_unknown_group() {
    let mut d = doc();
    apply_create(&mut d, &payload(r#"{"prefixes":["1.2.3.0/24"],"via":"ghost"}"#), Some(0))
        .expect("staged");
    let groups = group_names_in_doc(&d);
    let names: Vec<&str> = groups.iter().map(String::as_str).collect();
    let err = validate_route_array(&d, &names, Path::new("/tmp")).expect_err("bad via");
    assert!(
        format!("{err:#}").contains("ghost") || format!("{err:#}").contains("group"),
        "got: {err:#}"
    );
}

#[test]
fn group_names_are_extracted() {
    assert_eq!(group_names_in_doc(&doc()), vec!["main".to_string()]);
}
