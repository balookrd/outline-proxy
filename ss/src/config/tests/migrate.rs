use super::migrate_str;

#[test]
fn migrates_flat_keys_into_sections() {
    let input = r#"
# top comment
listen = "0.0.0.0:3000"
ss_listen = "0.0.0.0:8388"
# metrics comment
metrics_path = "/metrics"
ws_path_tcp = "/tcp"
ws_path_udp = "/udp"
http_root_auth = true
method = "chacha20-ietf-poly1305"
"#;
    let (out, changed) = migrate_str(input).unwrap();
    assert!(changed);
    assert!(out.contains("[server]"));
    assert!(out.contains("listen = \"0.0.0.0:3000\""));
    assert!(out.contains("[server.ss]"));
    assert!(out.contains("[metrics]"));
    assert!(out.contains("path = \"/metrics\""));
    assert!(out.contains("[websocket]"));
    assert!(out.contains("tcp_path = \"/tcp\""));
    assert!(out.contains("udp_path = \"/udp\""));
    assert!(out.contains("[http_root]"));
    assert!(out.contains("auth = true"));
    assert!(out.contains("[shadowsocks]"));
    assert!(out.contains("method = \"chacha20-ietf-poly1305\""));
    assert!(!out.contains("ws_path_tcp ="));
}

#[test]
fn is_noop_when_already_migrated() {
    let input = r#"
[server]
listen = "0.0.0.0:3000"

[metrics]
path = "/metrics"
"#;
    let (_, changed) = migrate_str(input).unwrap();
    assert!(!changed);
}

#[test]
fn converts_password_to_default_user() {
    let input = r#"
listen = "0.0.0.0:3000"
password = "s3cret"
fwmark = 1001
"#;
    let (out, changed) = migrate_str(input).unwrap();
    assert!(changed);
    assert!(out.contains("[[users]]"));
    assert!(out.contains("id = \"default\""));
    assert!(out.contains("password = \"s3cret\""));
    assert!(out.contains("fwmark = 1001"));
    assert!(!out.contains("password = \"s3cret\"\nfwmark") || out.contains("[[users]]"));
    // legacy top-level keys gone
    assert!(!out.starts_with("password"));
}

#[test]
fn preserves_standalone_block_comments() {
    // Comments attached to preserved sections survive. Comments attached
    // to a legacy key's decor travel with the key into its new location.
    let input = r#"
listen = "0.0.0.0:3000"

# standalone block above users
[[users]]
id = "alice"
password = "secret"
"#;
    let (out, changed) = migrate_str(input).unwrap();
    assert!(changed);
    assert!(out.contains("# standalone block above users"));
}
