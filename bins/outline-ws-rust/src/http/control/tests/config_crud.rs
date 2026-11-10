//! `PATCH /control/config`: the edit must never produce a file the next start
//! would refuse to load.

use clap::Parser;
use tempfile::TempDir;

use super::*;
use crate::config::{Args, load_config};

const BASE_CONFIG: &str = r#"
tcp_ws_url = "wss://example.com/secret/tcp"
method = "chacha20-ietf-poly1305"
password = "Secret0"

[socks5]
listen = "127.0.0.1:1080"
username = "alice"
password = "secret"
"#;

fn patch(json: serde_json::Value) -> WsConfigPatch {
    serde_json::from_value(json).expect("patch deserialises")
}

/// Runs the edit against `raw` as if it were the config at a real path.
async fn edit(raw: &str, patch: &WsConfigPatch) -> Result<String, PatchRejection> {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    let args = Args::parse_from(["test"]);
    patched_config(raw, patch, &path, Some(&args))
        .await
        .map(|doc| doc.to_string())
}

fn invalid_message(result: Result<String, PatchRejection>) -> String {
    match result {
        Err(PatchRejection::Invalid(message)) => message,
        other => panic!("expected the patch to be rejected as invalid, got {other:?}"),
    }
}

#[tokio::test]
async fn a_valid_patch_is_applied_and_the_result_loads() {
    let patched =
        edit(BASE_CONFIG, &patch(serde_json::json!({ "probe": { "interval_secs": 45 } })))
            .await
            .expect("valid patch is accepted");

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    std::fs::write(&path, &patched).unwrap();
    let config = load_config(&path, &Args::parse_from(["test"])).await.unwrap();
    assert_eq!(config.groups[0].probe.interval, std::time::Duration::from_secs(45));
}

/// `[[socks5.users]]` and the single `username`/`password` are mutually
/// exclusive in the loader. Switching between the two forms through a patch
/// must leave a file that loads, whichever direction it goes.
#[tokio::test]
async fn switching_socks5_auth_form_leaves_a_loadable_config() {
    let to_users = edit(
        BASE_CONFIG,
        &patch(serde_json::json!({
            "socks5": { "users": [{ "username": "bob", "password": "pw" }] }
        })),
    )
    .await
    .expect("single user -> users list is accepted");
    assert!(!to_users.contains("alice"), "single user survived next to the list: {to_users}");

    edit(
        &to_users,
        &patch(serde_json::json!({ "socks5": { "username": "carol", "password": "pw" } })),
    )
    .await
    .expect("users list -> single user is accepted");
}

#[tokio::test]
async fn a_zero_dial_timeout_is_rejected() {
    let result =
        edit(BASE_CONFIG, &patch(serde_json::json!({ "dial": { "timeout_secs": 0 } }))).await;
    let message = invalid_message(result);
    assert!(message.contains("timeout_secs"), "unexpected message: {message}");
}

#[cfg(feature = "tun")]
#[tokio::test]
async fn a_tun_mtu_below_the_floor_is_rejected() {
    let raw =
        format!("{BASE_CONFIG}\n[tun]\npath = \"/dev/net/tun\"\nname = \"ws0\"\nmtu = 1500\n");
    let result = edit(&raw, &patch(serde_json::json!({ "tun": { "mtu": 0 } }))).await;
    let message = invalid_message(result);
    assert!(message.contains("mtu"), "unexpected message: {message}");
}

/// A patch that repairs a config which currently does not load must go
/// through: the check is on the result, not on the starting point.
#[tokio::test]
async fn a_patch_that_repairs_a_broken_config_is_accepted() {
    let broken = format!("{BASE_CONFIG}\n[dial]\ntimeout_secs = 0\n");
    edit(&broken, &patch(serde_json::json!({ "dial": { "timeout_secs": 10 } })))
        .await
        .expect("repairing patch is accepted");
}

#[tokio::test]
async fn config_that_is_not_toml_is_reported_as_unreadable() {
    let result = edit("not = [toml", &patch(serde_json::json!({}))).await;
    assert!(matches!(result, Err(PatchRejection::UnreadableConfig(_))), "got {result:?}");
}
