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
control_url = "http://198.18.1.102:9191"
token_file = "__INST_TOKEN_FILE__"

[[ss.instances]]
name = "cloud1"
control_url = "https://cloud1.beerloga.su/rust-ss-exporter"
token_file = "__INST_TOKEN_FILE__"
"#,
    );

    let config = UiConfig::load(&path).expect("config loads");

    assert_eq!(config.token, "s3cr3t");
    assert_eq!(config.ws.len(), 1);
    assert_eq!(config.ws[0].name, "beelink102");
    assert_eq!(config.ws[0].token, "inst-tok");
    assert_eq!(config.ss.len(), 1);
    assert_eq!(config.ss[0].control_url, "https://cloud1.beerloga.su/rust-ss-exporter");
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
control_url = "http://198.18.1.102:9191"
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
