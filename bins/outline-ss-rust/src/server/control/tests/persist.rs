use super::*;
use crate::config::{CipherKind, OneOrManyCidr, UserEntry};

fn entry(id: &str, password: &str) -> UserEntry {
    UserEntry {
        id: id.to_owned(),
        password: Some(password.to_owned()),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

fn upsert(user: UserEntry) -> UserMutation {
    UserMutation::Upsert(Box::new(user))
}

/// A config shaped like a deployed one: several users, and real sections both
/// before AND after the `[[users]]` run. The sections after it are the ones a
/// whole-list rewrite is most likely to disturb.
const FLEET_CONFIG: &str = r#"# outline-ss-rust config.
[server]
listen = "0.0.0.0:443"

[websocket]
ws_path_ss = "/ss"

[shadowsocks]
method = "chacha20-ietf-poly1305"

# Users start here.
[[users]]
# The owner's laptop.
id = "alice"
password = "p-alice"   # rotate quarterly
fwmark = 1001

[[users]]
id = "mmv-mac"
password = "p-mac"

[[users]]
id = "beerloga"
password = "p-beerloga"
enabled = false

[control]
listen = "127.0.0.1:9190"
token = "control-secret"

[dashboard]
enabled = true

[cluster]
enabled = false

[tuning]
udp_nat_max_entries = 65536
"#;

/// Every id present in the patched document, in file order.
fn ids(doc: &str) -> Vec<String> {
    let parsed: toml_edit::DocumentMut = doc.parse().expect("patched config must parse");
    let users = parsed.get("users").expect("users key");
    if let Some(tables) = users.as_array_of_tables() {
        return tables
            .iter()
            .map(|t| t["id"].as_str().expect("id").to_owned())
            .collect();
    }
    users
        .as_array()
        .expect("users is neither array-of-tables nor array")
        .iter()
        .map(|v| {
            v.as_inline_table().expect("inline table")["id"]
                .as_str()
                .expect("id")
                .to_owned()
        })
        .collect()
}

/// One user's key in the patched document, as rendered TOML.
fn user_key(doc: &str, id: &str, key: &str) -> Option<String> {
    let parsed: toml_edit::DocumentMut = doc.parse().expect("patched config must parse");
    parsed
        .get("users")?
        .as_array_of_tables()?
        .iter()
        .find(|t| t.get("id").and_then(|i| i.as_str()) == Some(id))?
        .get(key)
        .map(|item| item.to_string().trim().to_owned())
}

/// The regression this module exists for: adding one user must not delete the
/// others, and must not touch any other section.
#[test]
fn creating_a_user_keeps_every_other_user_and_section() {
    let out = patch_toml(FLEET_CONFIG, &upsert(entry("cloud3", "p-cloud3"))).expect("patch");

    assert_eq!(
        ids(&out),
        vec!["alice", "mmv-mac", "beerloga", "cloud3"],
        "existing users lost or reordered:\n{out}"
    );
    for section in [
        "[server]",
        "[websocket]",
        "[shadowsocks]",
        "[control]",
        "[dashboard]",
        "[cluster]",
        "[tuning]",
    ] {
        assert!(out.contains(section), "section {section} lost:\n{out}");
    }
    assert!(out.contains(r#"token = "control-secret""#), "control token lost:\n{out}");
    assert!(out.contains("udp_nat_max_entries = 65536"), "tuning value lost:\n{out}");
    assert!(out.contains(r#"password = "p-alice""#), "alice's password changed:\n{out}");
}

/// The file keeps the shape an admin edits by hand: `[[users]]` tables (not one
/// inline `users = [...]` line), in place, with their comments.
#[test]
fn patching_preserves_table_layout_and_comments() {
    let out = patch_toml(FLEET_CONFIG, &upsert(entry("cloud3", "p-cloud3"))).expect("patch");

    assert_eq!(
        out.matches("[[users]]").count(),
        4,
        "users no longer stored as `[[users]]` tables:\n{out}"
    );
    assert!(!out.contains("users = ["), "users collapsed into an inline array:\n{out}");
    assert!(out.contains("# outline-ss-rust config."), "header comment lost:\n{out}");
    assert!(out.contains("# Users start here."), "section comment lost:\n{out}");
    assert!(out.contains("# The owner's laptop."), "in-block comment lost:\n{out}");
    assert!(out.contains("# rotate quarterly"), "inline value comment lost:\n{out}");
    // The new user lands inside the `[[users]]` run, not after `[tuning]`.
    let new_user = out.find(r#"id = "cloud3""#).expect("new user present");
    assert!(
        new_user < out.find("[control]").expect("control section"),
        "new user escaped the users run:\n{out}"
    );
}

/// An update rewrites only the keys that changed, in place.
#[test]
fn updating_a_user_touches_only_that_entry() {
    let mut updated = entry("alice", "p-alice-rotated");
    updated.fwmark = Some(1001);
    let out = patch_toml(FLEET_CONFIG, &upsert(updated)).expect("patch");

    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"], "user set changed:\n{out}");
    assert!(out.contains(r#"password = "p-alice-rotated""#), "new password missing:\n{out}");
    assert!(!out.contains(r#"password = "p-alice""#), "old password survived:\n{out}");
    assert!(
        out.contains("# rotate quarterly"),
        "comment beside the rotated value lost:\n{out}"
    );
    assert!(out.contains(r#"password = "p-mac""#), "other user's password changed:\n{out}");
}

/// Keys the user no longer has are dropped rather than left stale.
#[test]
fn updating_a_user_drops_keys_it_no_longer_has() {
    // `beerloga` is `enabled = false` on disk; unblocking clears the key.
    let out = patch_toml(FLEET_CONFIG, &upsert(entry("beerloga", "p-beerloga"))).expect("patch");

    assert!(
        user_key(&out, "beerloga", "enabled").is_none(),
        "stale `enabled` key survived:\n{out}"
    );
    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"], "user set changed:\n{out}");
    // `[cluster] enabled = false` is a different key in a different section.
    assert!(out.contains("[cluster]\nenabled = false"), "cluster section disturbed:\n{out}");
}

#[test]
fn blocking_a_user_writes_the_enabled_key() {
    let mut blocked = entry("alice", "p-alice");
    blocked.fwmark = Some(1001);
    blocked.enabled = Some(false);
    let out = patch_toml(FLEET_CONFIG, &upsert(blocked)).expect("patch");

    assert!(out.contains("enabled = false"), "block not written:\n{out}");
    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"], "user set changed:\n{out}");
}

#[test]
fn deleting_a_user_removes_only_that_entry() {
    let out = patch_toml(FLEET_CONFIG, &UserMutation::Remove("mmv-mac".to_owned())).expect("patch");

    assert_eq!(ids(&out), vec!["alice", "beerloga"], "wrong users removed:\n{out}");
    assert!(out.contains(r#"token = "control-secret""#), "control section lost:\n{out}");
    assert!(!out.contains("p-mac"), "deleted user's password survived:\n{out}");
}

/// Deleting a user the file never had is a no-op, not an error.
#[test]
fn deleting_an_absent_user_leaves_the_file_byte_identical() {
    let out = patch_toml(FLEET_CONFIG, &UserMutation::Remove("nobody".to_owned())).expect("patch");
    assert_eq!(out, FLEET_CONFIG);
}

/// Re-writing a user with exactly the state already on disk changes nothing —
/// `persist_user_mutation` uses this to skip the write entirely.
#[test]
fn no_op_upsert_leaves_the_file_byte_identical() {
    let mut same = entry("alice", "p-alice");
    same.fwmark = Some(1001);
    let out = patch_toml(FLEET_CONFIG, &upsert(same)).expect("patch");
    assert_eq!(out, FLEET_CONFIG);
}

/// A `[users.aliases]` sub-table stays a sub-table instead of collapsing into
/// the inline form serde emits.
#[test]
fn aliases_keep_their_sub_table_form() {
    let original = r#"[[users]]
id = "alice"
password = "p-alice"

[users.aliases]
alice-mobile = "10.0.0.0/8"

[tuning]
udp_nat_max_entries = 65536
"#;
    let mut updated = entry("alice", "p-alice");
    updated.aliases = Some(
        [
            ("alice-mobile".to_owned(), OneOrManyCidr::One("10.0.0.0/8".to_owned())),
            ("alice-office".to_owned(), OneOrManyCidr::One("192.0.2.0/24".to_owned())),
        ]
        .into_iter()
        .collect(),
    );

    let out = patch_toml(original, &upsert(updated)).expect("patch");

    assert!(out.contains("[users.aliases]"), "aliases collapsed to inline:\n{out}");
    assert!(out.contains(r#"alice-office = "192.0.2.0/24""#), "new alias missing:\n{out}");
    assert!(out.contains("[tuning]"), "later section lost:\n{out}");
    // The patched document still loads as the real config schema.
    let parsed: toml_edit::DocumentMut = out.parse().expect("parse round-trip");
    assert!(parsed.get("users").is_some());
}

/// A config left in the inline shape by older builds is patched in that same
/// shape — one entry at a time, without reformatting the rest.
#[test]
fn inline_users_array_is_patched_in_place() {
    let original = r#"users = [{ id = "alice", password = "p-alice" }, { id = "bob", password = "p-bob" }]

[tuning]
udp_nat_max_entries = 65536
"#;

    let out = patch_toml(original, &upsert(entry("cloud3", "p-cloud3"))).expect("patch");
    assert_eq!(ids(&out), vec!["alice", "bob", "cloud3"], "inline patch lost users:\n{out}");
    assert!(out.contains("[tuning]"), "later section lost:\n{out}");

    let out = patch_toml(original, &UserMutation::Remove("alice".to_owned())).expect("patch");
    assert_eq!(ids(&out), vec!["bob"], "inline remove hit the wrong entry:\n{out}");
}

/// A config with no `[[users]]` yet grows one, without disturbing what is there.
#[test]
fn first_user_is_appended_to_a_config_without_any() {
    let original = "[server]\nlisten = \"0.0.0.0:443\"\n";
    let out = patch_toml(original, &upsert(entry("alice", "p-alice"))).expect("patch");

    assert_eq!(ids(&out), vec!["alice"]);
    assert!(out.contains("[[users]]"), "not written as a table:\n{out}");
    assert!(out.contains(r#"listen = "0.0.0.0:443""#), "server section lost:\n{out}");
}

/// A `users` key of some other type is a config we do not understand; refuse
/// rather than replace it.
#[test]
fn foreign_users_key_is_refused() {
    let err =
        patch_toml("users = \"nope\"\n", &upsert(entry("alice", "p"))).expect_err("must refuse");
    assert!(format!("{err:#}").contains("refusing to rewrite"), "unexpected error: {err:#}");
}

#[test]
fn method_change_round_trips() {
    let mut updated = entry("mmv-mac", "p-mac");
    updated.method = Some(CipherKind::Aes256Gcm);
    let out = patch_toml(FLEET_CONFIG, &upsert(updated)).expect("patch");
    assert!(out.contains(r#"method = "aes-256-gcm""#), "method not written:\n{out}");
    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"]);
}
