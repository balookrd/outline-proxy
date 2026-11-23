use std::io::Write;

use super::*;

/// Writes `body` to a temp file plus a sibling token file, returns both paths.
fn write_config(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("ui-token");
    std::fs::write(&secret, "s3cr3t").unwrap();
    let inst = dir.path().join("inst-token");
    std::fs::write(&inst, "inst-tok").unwrap();
    let path = dir.path().join("ui.toml");
    let body = body
        .replace("__UI_TOKEN_FILE__", secret.to_str().unwrap())
        .replace("__INST_TOKEN_FILE__", inst.to_str().unwrap());
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    (dir, path)
}

#[test]
fn loads_instances_for_both_trees_and_reads_token_files() {
    let (_dir, path) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"
token_file = "__UI_TOKEN_FILE__"

[[ws.instances]]
name = "beelink102"
control_url = "http://198.51.100.102:9191"
token_file = "__INST_TOKEN_FILE__"

[[ss.instances]]
name = "cloud1"
control_url = "https://cloud1.example.com/rust-ss-exporter"
token_file = "__INST_TOKEN_FILE__"
"#,
    );

    let config = UiConfig::load(&path).expect("config loads");

    assert_eq!(config.token, "s3cr3t");
    assert_eq!(config.ws.len(), 1);
    assert_eq!(config.ws[0].name, "beelink102");
    assert_eq!(config.ws[0].token, "inst-tok");
    assert_eq!(config.ss.len(), 1);
    assert_eq!(config.ss[0].control_url, "https://cloud1.example.com/rust-ss-exporter");
}

/// The listener is on 0.0.0.0 inside the pod, and reaching it grants every
/// instance token. An unauthenticated UI is a configuration error, not a
/// permissive default.
#[test]
fn missing_token_is_rejected() {
    let (_dir, path) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"

[[ws.instances]]
name = "beelink102"
control_url = "http://198.51.100.102:9191"
token_file = "__INST_TOKEN_FILE__"
"#,
    );

    let error = UiConfig::load(&path).expect_err("must refuse an unauthenticated listener");
    assert!(
        error.to_string().contains("token"),
        "error should name the missing token, got: {error}"
    );
}

/// A trailing newline is what `echo` and most secret mounts produce; carrying it
/// into the Authorization header makes every request fail with a 401 nobody can
/// explain.
#[test]
fn token_file_trailing_newline_is_trimmed() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("ui-token");
    std::fs::write(&secret, "s3cr3t\n").unwrap();
    let path = dir.path().join("ui.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\nlisten = \"0.0.0.0:9000\"\ntoken_file = \"{}\"\n",
            secret.to_str().unwrap()
        ),
    )
    .unwrap();

    let config = UiConfig::load(&path).unwrap();

    assert_eq!(config.token, "s3cr3t");
}

#[test]
fn empty_token_literal_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ui.toml");
    std::fs::write(&path, "[server]\nlisten = \"0.0.0.0:9000\"\ntoken = \"   \"\n").unwrap();

    let error = UiConfig::load(&path).expect_err("must refuse empty token literal");
    assert!(
        error.to_string().contains("token must not be empty"),
        "error should indicate empty token, got: {error}"
    );
}

#[test]
fn empty_token_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("empty-token");
    std::fs::write(&secret, "  \n\t \n").unwrap();
    let path = dir.path().join("ui.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\nlisten = \"0.0.0.0:9000\"\ntoken_file = \"{}\"\n",
            secret.to_str().unwrap()
        ),
    )
    .unwrap();

    let error = UiConfig::load(&path).expect_err("must refuse empty token file");
    assert!(
        error.to_string().contains("is empty"),
        "error should indicate empty token file, got: {error}"
    );
}

#[test]
fn debug_output_hides_every_token() {
    let config = UiConfig {
        listen: "127.0.0.1:8080".parse().unwrap(),
        token: "s3cr3t-ui-token".to_owned(),
        request_timeout_secs: 10,
        refresh_interval_secs: 5,
        allowed_hosts: vec!["ui.example".to_owned()],
        ws: vec![InstanceConfig {
            name: "node-a".to_owned(),
            control_url: "http://10.0.0.1:9191".to_owned(),
            token: "s3cr3t-instance-token".to_owned(),
            public_host: None,
            mesh_addr: None,
        }],
        ss: Vec::new(),
        ss_clusters: Vec::new(),
    };
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("s3cr3t-ui-token"), "listener token leaked: {rendered}");
    assert!(!rendered.contains("s3cr3t-instance-token"), "instance token leaked: {rendered}");
    assert!(rendered.contains("node-a"), "instance name missing: {rendered}");
}

#[test]
fn loads_ss_clusters_and_validates_membership() {
    let (_dir, path) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"
token_file = "__UI_TOKEN_FILE__"

[[ss.instances]]
name = "relay-a"
control_url = "https://relay-a.fleet.example/rust-ss-exporter"
token_file = "__INST_TOKEN_FILE__"
public_host = "relay-a.fleet.example"
mesh_addr = "198.51.100.10:9443"

[[ss.instances]]
name = "relay-b"
control_url = "https://relay-b.fleet.example/rust-ss-exporter"
token_file = "__INST_TOKEN_FILE__"
public_host = "relay-b.fleet.example"
mesh_addr = "198.51.100.11:9443"

[[ss.clusters]]
name = "cloud"
members = ["relay-a", "relay-b"]
subscription_nodes = ["relay-a.fleet.example", "relay-b.fleet.example"]
"#,
    );

    let cfg = UiConfig::load(&path).expect("clusters config loads");
    assert_eq!(cfg.ss[0].public_host.as_deref(), Some("relay-a.fleet.example"));
    assert_eq!(cfg.ss[0].mesh_addr.as_deref(), Some("198.51.100.10:9443"));
    assert_eq!(cfg.ss_clusters.len(), 1);
    assert_eq!(cfg.ss_clusters[0].name, "cloud");
    assert_eq!(cfg.ss_clusters[0].members, vec!["relay-a", "relay-b"]);
    assert_eq!(
        cfg.ss_clusters[0].subscription_nodes,
        vec!["relay-a.fleet.example", "relay-b.fleet.example"]
    );
}

#[test]
fn rejects_invalid_ss_clusters() {
    let (_dir, unknown_member) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"
token_file = "__UI_TOKEN_FILE__"

[[ss.instances]]
name = "relay-a"
control_url = "http://127.0.0.1:9191"
token_file = "__INST_TOKEN_FILE__"

[[ss.clusters]]
name = "cloud"
members = ["relay-a", "missing"]
"#,
    );
    assert!(UiConfig::load(&unknown_member).is_err());

    let (_dir2, overlapping) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"
token_file = "__UI_TOKEN_FILE__"

[[ss.instances]]
name = "relay-a"
control_url = "http://127.0.0.1:9191"
token_file = "__INST_TOKEN_FILE__"

[[ss.clusters]]
name = "c1"
members = ["relay-a"]

[[ss.clusters]]
name = "c2"
members = ["relay-a"]
"#,
    );
    assert!(UiConfig::load(&overlapping).is_err());

    let (_dir3, slash_name) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"
token_file = "__UI_TOKEN_FILE__"

[[ss.instances]]
name = "relay-a"
control_url = "http://127.0.0.1:9191"
token_file = "__INST_TOKEN_FILE__"

[[ss.clusters]]
name = "bad/name"
members = ["relay-a"]
"#,
    );
    assert!(UiConfig::load(&slash_name).is_err());
}
