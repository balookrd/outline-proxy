use toml_edit::DocumentMut;

use super::group_entries_from_doc;

const BASE: &str = "\
[[uplink_group]]
name = \"main\"
mode = \"active_active\"

[[uplink_group]]
name = \"backup\"
mode = \"active_passive\"

[[outline.uplinks]]
name = \"cloud1\"
group = \"main\"
transport = \"ss\"
";

#[test]
fn entries_carry_name_count_and_config() {
    let doc = BASE.parse::<DocumentMut>().unwrap();
    let entries = group_entries_from_doc(&doc);
    assert_eq!(entries.len(), 2);
    let main = entries.iter().find(|e| e.name == "main").expect("main present");
    assert_eq!(main.uplink_count, 1);
    assert!(main.config.is_some(), "config round-tripped");
    let backup = entries.iter().find(|e| e.name == "backup").expect("backup present");
    assert_eq!(backup.uplink_count, 0, "empty group counts zero");
}
