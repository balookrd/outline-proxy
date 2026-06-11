use super::*;
use crate::config::{CipherKind, UserEntry};

fn sample_users() -> Vec<UserEntry> {
    vec![
        UserEntry {
            id: "alice".to_owned(),
            password: Some("old-pass".to_owned()),
            fwmark: Some(1001),
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: None,
            ws_path_vless: None,
            xhttp_path_vless: None,
            enabled: None,
        },
        UserEntry {
            id: "bob".to_owned(),
            password: Some("new-pass".to_owned()),
            fwmark: None,
            method: Some(CipherKind::Aes256Gcm),
            ws_path_tcp: Some("/bob/tcp".to_owned()),
            ws_path_udp: Some("/bob/udp".to_owned()),
            vless_id: None,
            ws_path_vless: None,
            xhttp_path_vless: None,
            enabled: Some(false),
        },
    ]
}

#[test]
fn toml_rewrite_preserves_comments_and_unrelated_keys() {
    let original = r#"
# Header comment that must survive.
listen = "0.0.0.0:3000"  # listener comment
method = "chacha20-ietf-poly1305"

# Separator comment.
[tuning]
udp_nat_idle_timeout_secs = 300  # tuning comment

# Old users block follows.
[[users]]
id = "alice"
password = "stale"
"#;

    let out = rewrite_toml(original, &sample_users()).expect("rewrite_toml");

    // Comments preserved outside the `users` key.
    assert!(
        out.contains("# Header comment that must survive."),
        "header comment lost:\n{out}"
    );
    assert!(out.contains("# listener comment"), "inline listener comment lost:\n{out}");
    assert!(out.contains("# Separator comment."), "separator comment lost:\n{out}");
    assert!(out.contains("# tuning comment"), "tuning inline comment lost:\n{out}");
    // Unrelated keys untouched.
    assert!(out.contains(r#"listen = "0.0.0.0:3000""#), "listen value changed:\n{out}");
    assert!(out.contains("udp_nat_idle_timeout_secs = 300"), "tuning value changed:\n{out}");
    // New users present, old value gone.
    assert!(out.contains("new-pass"), "new user payload missing:\n{out}");
    assert!(!out.contains(r#"password = "stale""#), "old user payload survived:\n{out}");
    // Result round-trips back into the real config schema.
    let parsed: toml_edit::DocumentMut = out.parse().expect("parse round-trip");
    assert!(parsed.get("users").is_some());
}
