use std::{fs, path::PathBuf};

use super::*;

/// Per-test scratch directory, unique per test name and process.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("outline-ss-dashboard-{}-{}", name, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn file_config(dashboard_extra: &str) -> FileConfig {
    let toml = format!(
        r#"
[server]
listen = "0.0.0.0:3000"

[dashboard]
listen = "127.0.0.1:7002"
{dashboard_extra}

[[dashboard.instances]]
name = "local"
control_url = "http://127.0.0.1:7001"
token = "instance-token"
"#
    );
    toml::from_str(&toml).expect("dashboard config parses")
}

/// Instance tokens keep their own file/inline handling; pinned before the
/// dashboard listener token started sharing that code.
#[test]
fn reads_instance_token_from_file_relative_to_the_config() {
    let dir = scratch("instance-token-file");
    fs::write(dir.join("instance.token"), " instance-file-secret\n").unwrap();
    let file: FileConfig = toml::from_str(
        r#"
[server]
listen = "0.0.0.0:3000"

[dashboard]
listen = "127.0.0.1:7002"

[[dashboard.instances]]
name = "local"
control_url = "http://127.0.0.1:7001"
token_file = "instance.token"
"#,
    )
    .unwrap();

    let config = resolve_dashboard_config(&file, &dir).unwrap().unwrap();

    assert_eq!(config.instances[0].token, "instance-file-secret");
}

#[test]
fn dashboard_listener_has_no_token_by_default() {
    let config = resolve_dashboard_config(&file_config(""), Path::new("."))
        .unwrap()
        .unwrap();

    assert_eq!(config.token, None);
}

#[test]
fn resolves_inline_dashboard_token() {
    let config = resolve_dashboard_config(&file_config(r#"token = "s3cr3t""#), Path::new("."))
        .unwrap()
        .unwrap();

    assert_eq!(config.token.as_deref(), Some("s3cr3t"));
}

#[test]
fn reads_dashboard_token_from_file_relative_to_the_config() {
    let dir = scratch("token-file");
    fs::write(dir.join("dashboard.token"), "  file-secret\n").unwrap();

    let config = resolve_dashboard_config(&file_config(r#"token_file = "dashboard.token""#), &dir)
        .unwrap()
        .unwrap();

    assert_eq!(config.token.as_deref(), Some("file-secret"));
}

#[test]
fn rejects_dashboard_token_and_token_file_together() {
    let error = resolve_dashboard_config(
        &file_config("token = \"s3cr3t\"\ntoken_file = \"dashboard.token\""),
        Path::new("."),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("token_file"), "unexpected error: {error}");
}

#[test]
fn rejects_empty_dashboard_token_file() {
    let dir = scratch("empty-token-file");
    fs::write(dir.join("dashboard.token"), "   \n").unwrap();

    let error = resolve_dashboard_config(&file_config(r#"token_file = "dashboard.token""#), &dir)
        .unwrap_err()
        .to_string();

    assert!(error.contains("empty"), "unexpected error: {error}");
}
