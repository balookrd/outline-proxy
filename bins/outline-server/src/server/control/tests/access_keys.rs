use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json,
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
};

use super::*;

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> TempDirGuard {
    let dir = std::env::temp_dir().join(format!(
        "outline-ak-test-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    TempDirGuard(dir)
}

fn state_with_mock_generator(
    cfg_path: &Path,
    mock_script: &Path,
    timeout: Duration,
) -> ControlState {
    let text = std::fs::read_to_string(cfg_path).unwrap();
    let mut cfg = crate::config::parse_and_validate(&text).unwrap();
    cfg.config_path = Some(cfg_path.to_path_buf());
    let cfg = Arc::new(cfg);
    let manager = Arc::new(crate::server::control::manager::manager_for((*cfg).clone()));
    ControlState {
        manager,
        config: cfg,
        token: Arc::from("test-token"),
        access_keys: Some(AccessKeysRunnerConfig {
            generator: mock_script.to_path_buf(),
            python: PathBuf::from("python3"),
            timeout,
        }),
    }
}

#[tokio::test]
async fn regenerate_and_user_links_invoke_generator_and_map_statuses() {
    let dir = temp_dir("mock");
    let secret_dir = dir.0.join("secret-keys-subdir");
    std::fs::create_dir_all(&secret_dir).unwrap();
    let cfg_path = dir.0.join("config.toml");
    let mock_py = dir.0.join("mock_gen.py");
    let args_log = dir.0.join("args.json");

    let cfg_toml = format!(
        r#"
[server]
listen = "127.0.0.1:443"
cert_path = "cert.pem"
key_path = "key.pem"

[server.h3]
listen = "127.0.0.1:443"

[access_keys]
public_host = "edge.fleet.example"
public_scheme = "wss"
write_dir = "{}"
nodes = ["relay-a.fleet.example", "relay-b.fleet.example"]

[[users]]
id = "alice"
password = "pw-alice"
"#,
        secret_dir.display()
    );
    std::fs::write(&cfg_path, cfg_toml).unwrap();

    let script = format!(
        r#"import json, sys, time
args = sys.argv[1:]
with open({args_log:?}, "w") as f:
    json.dump(args, f)
if "--links-json" in args:
    uid = args[args.index("--user") + 1]
    if uid == "disabled":
        sys.stderr.write("user is disabled for {secret}\n")
        sys.exit(2)
    if uid == "missing":
        sys.stderr.write("user not found\n")
        sys.exit(3)
    if uid == "slow":
        time.sleep(2.0)
    print(json.dumps({{
        "user": uid,
        "enabled": True,
        "outline_url": "ssconf://edge.fleet.example/alice.conf",
        "happ_url": "https://edge.fleet.example/alice.json",
        "ws_url": "https://edge.fleet.example/alice.toml",
        "txt_url": "https://edge.fleet.example/alice.txt",
        "share_links": ["ss://example"],
        "artifacts": {{"conf": "{{}}"}},
        "warnings": []
    }}))
else:
    print(json.dumps({{
        "nodes": ["relay-a.fleet.example", "relay-b.fleet.example"],
        "written": [{{"user": "alice", "files": ["alice.conf", "alice.json", "alice.toml", "alice.txt"]}}],
        "pruned": ["stale.conf"],
        "warnings": []
    }}))
"#,
        args_log = args_log.to_string_lossy(),
        secret = secret_dir.to_string_lossy()
    );
    std::fs::write(&mock_py, script).unwrap();

    let state = state_with_mock_generator(&cfg_path, &mock_py, Duration::from_secs(5));

    // 1. Regenerate default -> uses [access_keys].nodes, passes --prune and --file-extension .conf
    let resp = regenerate(State(state.clone()), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let regen_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(regen_json["pruned"][0], "stale.conf");
    let recorded: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&args_log).unwrap()).unwrap();
    assert!(recorded.contains(&"--prune".to_string()));
    assert!(recorded.contains(&"--file-extension".to_string()));
    assert!(recorded.contains(&".conf".to_string()));
    assert!(recorded.contains(&"relay-a.fleet.example".to_string()));
    assert!(recorded.contains(&"relay-b.fleet.example".to_string()));

    // 2. Get user access keys (active) -> 200 OK
    let ok = get_user_access_keys(
        State(state.clone()),
        AxumPath("alice".to_string()),
        Query(UserAccessKeysQuery::default()),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let ok_json: Value =
        serde_json::from_slice(&axum::body::to_bytes(ok.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(ok_json["user"], "alice");

    // 3. Disabled -> 409 Conflict with redacted write_dir
    let dis = get_user_access_keys(
        State(state.clone()),
        AxumPath("disabled".to_string()),
        Query(UserAccessKeysQuery::default()),
    )
    .await;
    assert_eq!(dis.status(), StatusCode::CONFLICT);
    let dis_text = String::from_utf8(
        axum::body::to_bytes(dis.into_body(), 64 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!dis_text.contains("secret-keys-subdir"), "write_dir leaked: {dis_text}");
    assert!(dis_text.contains("<redacted>"));

    // 4. Not found -> 404 Not Found
    let nf = get_user_access_keys(
        State(state.clone()),
        AxumPath("missing".to_string()),
        Query(UserAccessKeysQuery::default()),
    )
    .await;
    assert_eq!(nf.status(), StatusCode::NOT_FOUND);

    // 5. Invalid id or node host -> 400 Bad Request
    let bad_id = get_user_access_keys(
        State(state.clone()),
        AxumPath("-bad".to_string()),
        Query(UserAccessKeysQuery::default()),
    )
    .await;
    assert_eq!(bad_id.status(), StatusCode::BAD_REQUEST);

    let bad_node = regenerate(
        State(state),
        Some(Json(RegenerateRequest {
            nodes: Some(vec!["--inject".to_string()]),
            prune: Some(true),
        })),
    )
    .await;
    assert_eq!(bad_node.status(), StatusCode::BAD_REQUEST);

    // 6. Timeout -> 504 Gateway Timeout
    let fast_timeout_state =
        state_with_mock_generator(&cfg_path, &mock_py, Duration::from_millis(150));
    let timed = get_user_access_keys(
        State(fast_timeout_state),
        AxumPath("slow".to_string()),
        Query(UserAccessKeysQuery::default()),
    )
    .await;
    assert_eq!(timed.status(), StatusCode::GATEWAY_TIMEOUT);
}
