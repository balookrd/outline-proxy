use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State as AxumState};
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

use crate::backend::Backend;
use crate::config::{ClusterConfig, InstanceConfig};
use crate::ss::{SsState, router};

#[derive(Clone)]
struct MockControlState {
    name: String,
    fail_create: Arc<Mutex<bool>>,
    config: Arc<Mutex<Value>>,
    users: Arc<Mutex<Vec<Value>>>,
    calls: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl MockControlState {
    fn new(name: &str, shard_id: u8, psk_fp: &str, peers: Value, users: Vec<Value>) -> Self {
        Self {
            name: name.to_string(),
            fail_create: Arc::new(Mutex::new(false)),
            config: Arc::new(Mutex::new(json!({
                "config_path": "/etc/outline-server/config.toml",
                "restart_pending": false,
                "cluster": {
                    "enabled": true,
                    "shard_id": shard_id,
                    "has_cluster_psk": true,
                    "cluster_psk": "********",
                    "psk_fingerprint": psk_fp,
                    "mesh_listen": format!("198.51.100.{}:9443", 10 + shard_id),
                    "peers": peers
                },
                "server": {
                    "listen": "0.0.0.0:443",
                    "max_connections_per_ip": 32,
                    "certs": [],
                    "h3_alpn": ["h3"]
                },
                "shadowsocks": { "method": "2022-blake3-aes-256-gcm" },
                "access_keys": {
                    "public_host": format!("{name}.fleet.example"),
                    "public_scheme": "wss",
                    "nodes": ["relay-a.fleet.example", "relay-b.fleet.example"]
                },
                "tuning_profile": "large",
                "endpoints": [
                    { "path": "/ws", "kind": "ws_ss", "protocol": "shadowsocks", "transport": "websocket", "padded": false }
                ]
            }))),
            users: Arc::new(Mutex::new(users)),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

async fn spawn_mock_node(state: MockControlState) -> SocketAddr {
    let app = Router::new()
        .route(
            "/control/config",
            get(|AxumState(s): AxumState<MockControlState>| async move {
                let cfg = s.config.lock().unwrap().clone();
                (StatusCode::OK, Json(cfg))
            })
            .patch(
                |AxumState(s): AxumState<MockControlState>, Json(patch): Json<Value>| async move {
                    s.calls.lock().unwrap().push(("PATCH".into(), "/control/config".into(), patch.clone()));
                    let requires_restart = patch
                        .as_object()
                        .is_some_and(|m| m.keys().any(|k| k != "access_keys"));
                    (
                        StatusCode::OK,
                        Json(json!({ "ok": true, "requires_restart": requires_restart })),
                    )
                },
            ),
        )
        .route(
            "/control/users",
            get(|AxumState(s): AxumState<MockControlState>| async move {
                let users = s.users.lock().unwrap().clone();
                (StatusCode::OK, Json(json!({ "users": users })))
            })
            .post(
                |AxumState(s): AxumState<MockControlState>, Json(body): Json<Value>| async move {
                    s.calls.lock().unwrap().push(("POST".into(), "/control/users".into(), body.clone()));
                    if *s.fail_create.lock().unwrap() {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "injected failure" })),
                        );
                    }
                    let id = body["id"].as_str().unwrap().to_string();
                    let view = json!({
                        "id": id,
                        "enabled": body.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                        "method": body.get("method").cloned().unwrap_or(Value::Null),
                        "fwmark": Value::Null,
                        "aliases": Value::Null,
                        "has_password": body.get("password").is_some(),
                        "has_vless_id": body.get("vless_id").is_some(),
                        "password_fp": "aaaaaaaaaaaa",
                        "vless_id_fp": Value::Null
                    });
                    s.users.lock().unwrap().push(view.clone());
                    (StatusCode::CREATED, Json(view))
                },
            ),
        )
        .route(
            "/control/users/{id}",
            patch(
                |AxumState(s): AxumState<MockControlState>,
                 AxumPath(id): AxumPath<String>,
                 Json(body): Json<Value>| async move {
                    s.calls
                        .lock()
                        .unwrap()
                        .push(("PATCH".into(), format!("/control/users/{id}"), body));
                    (StatusCode::OK, Json(json!({ "id": id, "enabled": true })))
                },
            )
            .delete(
                |AxumState(s): AxumState<MockControlState>, AxumPath(id): AxumPath<String>| async move {
                    s.calls
                        .lock()
                        .unwrap()
                        .push(("DELETE".into(), format!("/control/users/{id}"), Value::Null));
                    let mut guard = s.users.lock().unwrap();
                    let before = guard.len();
                    guard.retain(|u| u.get("id").and_then(Value::as_str) != Some(id.as_str()));
                    if guard.len() == before {
                        (StatusCode::NOT_FOUND, Json(json!({ "error": "user not found" })))
                    } else {
                        (StatusCode::NO_CONTENT, Json(Value::Null))
                    }
                },
            ),
        )
        .route(
            "/control/access-keys/regenerate",
            post(
                |AxumState(s): AxumState<MockControlState>, Json(body): Json<Value>| async move {
                    s.calls.lock().unwrap().push((
                        "POST".into(),
                        "/control/access-keys/regenerate".into(),
                        body.clone(),
                    ));
                    (
                        StatusCode::OK,
                        Json(json!({
                            "nodes": body.get("nodes").cloned().unwrap_or(json!([s.name])),
                            "written": [{"user": "alice", "files": ["alice.conf"]}],
                            "pruned": ["stale.conf"],
                            "warnings": []
                        })),
                    )
                },
            ),
        )
        .route(
            "/control/users/{id}/access-keys",
            get(
                |AxumState(s): AxumState<MockControlState>,
                 AxumPath(id): AxumPath<String>,
                 Query(q): Query<HashMap<String, String>>| async move {
                    let nodes = q.get("nodes").cloned().unwrap_or_default();
                    (
                        StatusCode::OK,
                        Json(json!({
                            "user": id,
                            "enabled": true,
                            "outline_url": format!("ssconf://{}.fleet.example/{id}.conf", s.name),
                            "happ_url": null,
                            "ws_url": null,
                            "txt_url": null,
                            "share_links": [format!("ss://example@{nodes}#{id}")],
                            "artifacts": { "conf": "{}" },
                            "warnings": []
                        })),
                    )
                },
            ),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn json_body(res_bytes: &[u8]) -> Value {
    serde_json::from_slice(res_bytes).unwrap()
}

#[tokio::test]
async fn cluster_config_drift_mesh_health_and_deep_patch() {
    let node_a = MockControlState::new(
        "relay-a",
        0,
        "aabbccddeeff",
        json!([{ "shard": 1, "addr": "198.51.100.11:9443" }]),
        vec![],
    );
    let node_b = MockControlState::new(
        "relay-b",
        1,
        "aabbccddeeff",
        json!([{ "shard": 0, "addr": "198.51.100.10:9443" }]),
        vec![],
    );
    // Introduce drift on node_b tuning_profile and restart_pending = true
    {
        let mut cfg_b = node_b.config.lock().unwrap();
        cfg_b["tuning_profile"] = json!("medium");
        cfg_b["restart_pending"] = json!(true);
    }

    let addr_a = spawn_mock_node(node_a.clone()).await;
    let addr_b = spawn_mock_node(node_b.clone()).await;

    let state = SsState {
        backend: Arc::new(Backend::new(5)),
        instances: Arc::from(vec![
            InstanceConfig {
                name: "relay-a".into(),
                control_url: format!("http://{addr_a}"),
                token: "t1".into(),
                public_host: Some("relay-a.fleet.example".into()),
                mesh_addr: Some("198.51.100.10:9443".into()),
            },
            InstanceConfig {
                name: "relay-b".into(),
                control_url: format!("http://{addr_b}"),
                token: "t2".into(),
                public_host: Some("relay-b.fleet.example".into()),
                mesh_addr: Some("198.51.100.11:9443".into()),
            },
        ]),
        clusters: Arc::from(vec![ClusterConfig {
            name: "cloud".into(),
            members: vec!["relay-a".into(), "relay-b".into()],
            subscription_nodes: vec![
                "relay-a.fleet.example".into(),
                "relay-b.fleet.example".into(),
            ],
        }]),
        refresh_ms: 5000,
    };

    let app = router(state);
    let cfg_res = app
        .clone()
        .oneshot(
            Request::get("/dashboard/api/clusters/cloud/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cfg_res.status(), StatusCode::OK);
    let cfg_json =
        json_body(&axum::body::to_bytes(cfg_res.into_body(), 1024 * 1024).await.unwrap());
    assert!(
        cfg_json["drift"]
            .as_array()
            .unwrap()
            .contains(&json!("tuning_profile"))
    );
    assert_eq!(cfg_json["mesh_health"]["psk_match"], true);
    assert_eq!(cfg_json["mesh_health"]["shards_unique"], true);
    assert_eq!(cfg_json["mesh_health"]["peers_symmetric"], true);
    assert_eq!(cfg_json["mesh_health"]["restart_pending_nodes"], json!(["relay-b"]));

    // PATCH config merges shared.server with per_node[relay-a].server
    let patch_body = json!({
        "shared": { "server": { "max_connections_per_ip": 64 } },
        "per_node": {
            "relay-a": { "server": { "listen": "0.0.0.0:8443" } }
        }
    });
    let patch_res = app
        .oneshot(
            Request::patch("/dashboard/api/clusters/cloud/config")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&patch_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patch_res.status(), StatusCode::OK);

    let a_calls = node_a.calls.lock().unwrap();
    assert_eq!(a_calls[0].1, "/control/config");
    assert_eq!(a_calls[0].2["server"]["max_connections_per_ip"], 64);
    assert_eq!(a_calls[0].2["server"]["listen"], "0.0.0.0:8443");
}

#[tokio::test]
async fn cluster_user_crud_preflight_rollback_idempotent_delete_and_subscriptions() {
    let node_a = MockControlState::new(
        "relay-a",
        0,
        "aabbccddeeff",
        json!([{ "shard": 1, "addr": "198.51.100.11:9443" }]),
        vec![json!({
            "id": "alice",
            "enabled": true,
            "has_password": true,
            "has_vless_id": false,
            "password_fp": "111111111111"
        })],
    );
    let node_b = MockControlState::new(
        "relay-b",
        1,
        "aabbccddeeff",
        json!([{ "shard": 0, "addr": "198.51.100.10:9443" }]),
        vec![],
    );

    let addr_a = spawn_mock_node(node_a.clone()).await;
    let addr_b = spawn_mock_node(node_b.clone()).await;

    let state = SsState {
        backend: Arc::new(Backend::new(5)),
        instances: Arc::from(vec![
            InstanceConfig {
                name: "relay-a".into(),
                control_url: format!("http://{addr_a}"),
                token: "t1".into(),
                public_host: None,
                mesh_addr: None,
            },
            InstanceConfig {
                name: "relay-b".into(),
                control_url: format!("http://{addr_b}"),
                token: "t2".into(),
                public_host: None,
                mesh_addr: None,
            },
        ]),
        clusters: Arc::from(vec![ClusterConfig {
            name: "cloud".into(),
            members: vec!["relay-a".into(), "relay-b".into()],
            subscription_nodes: vec![
                "relay-a.fleet.example".into(),
                "relay-b.fleet.example".into(),
            ],
        }]),
        refresh_ms: 5000,
    };
    let app = router(state);

    // 1. list_users -> alice is partial (only on relay-a)
    let list_res = app
        .clone()
        .oneshot(
            Request::get("/dashboard/api/clusters/cloud/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list_json =
        json_body(&axum::body::to_bytes(list_res.into_body(), 1024 * 1024).await.unwrap());
    assert_eq!(list_json["users"][0]["id"], "alice");
    assert_eq!(list_json["users"][0]["sync_status"], "partial");
    assert_eq!(list_json["users"][0]["missing_on"], json!(["relay-b"]));

    // 2. create_user pre-flight catches existing alice on relay-a -> 409 Conflict without calling POST on relay-b
    let dup_res = app
        .clone()
        .oneshot(
            Request::post("/dashboard/api/clusters/cloud/users")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "id": "alice", "password": "p" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dup_res.status(), StatusCode::CONFLICT);
    assert!(node_b.users.lock().unwrap().is_empty());

    // 3. create_user rollback when relay-b fails after relay-a succeeds
    *node_b.fail_create.lock().unwrap() = true;
    let fail_res = app
        .clone()
        .oneshot(
            Request::post("/dashboard/api/clusters/cloud/users")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "id": "bob", "password": "p" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fail_res.status(), StatusCode::BAD_GATEWAY);
    let fail_json =
        json_body(&axum::body::to_bytes(fail_res.into_body(), 1024 * 1024).await.unwrap());
    assert_eq!(fail_json["rolled_back"], true);
    assert!(
        node_a.users.lock().unwrap().iter().all(|u| u["id"] != "bob"),
        "bob must be rolled back on relay-a"
    );

    // 4. create_user succeeds on both
    *node_b.fail_create.lock().unwrap() = false;
    let ok_create = app
        .clone()
        .oneshot(
            Request::post("/dashboard/api/clusters/cloud/users")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "id": "bob", "password": "p" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_create.status(), StatusCode::CREATED);
    assert!(node_a.users.lock().unwrap().iter().any(|u| u["id"] == "bob"));
    assert!(node_b.users.lock().unwrap().iter().any(|u| u["id"] == "bob"));

    // 5. idempotent delete_user when alice only exists on relay-a (404 on relay-b -> ok with already_absent)
    let del_res = app
        .clone()
        .oneshot(
            Request::delete("/dashboard/api/clusters/cloud/users/alice")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_res.status(), StatusCode::OK);
    let del_json =
        json_body(&axum::body::to_bytes(del_res.into_body(), 1024 * 1024).await.unwrap());
    assert_eq!(del_json["ok"], true);
    let b_del = del_json["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["instance"] == "relay-b")
        .unwrap();
    assert_eq!(b_del["already_absent"], true);

    // 6. regenerate_access_keys propagates cluster.subscription_nodes and prune=true
    let regen_res = app
        .clone()
        .oneshot(
            Request::post("/dashboard/api/clusters/cloud/access-keys/regenerate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(regen_res.status(), StatusCode::OK);
    let regen_json = json_body(
        &axum::body::to_bytes(regen_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    );
    assert_eq!(regen_json["nodes"], json!(["relay-a.fleet.example", "relay-b.fleet.example"]));

    // 7. get_user_access_keys passes cluster.subscription_nodes
    let links_res = app
        .oneshot(
            Request::get("/dashboard/api/clusters/cloud/users/bob/access-keys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(links_res.status(), StatusCode::OK);
    let links_json = json_body(
        &axum::body::to_bytes(links_res.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    );
    assert_eq!(links_json["mode"], "cluster");
    assert_eq!(links_json["user"], "bob");
}

#[tokio::test]
async fn auto_discovers_clusters_by_matching_psk_fingerprint() {
    let node_1 = MockControlState::new("exit-a", 0, "deadbeef1234", json!([]), vec![]);
    let node_2 = MockControlState::new("exit-b", 1, "deadbeef1234", json!([]), vec![]);
    let addr_1 = spawn_mock_node(node_1).await;
    let addr_2 = spawn_mock_node(node_2).await;

    let state = SsState {
        backend: Arc::new(Backend::new(5)),
        instances: Arc::from(vec![
            InstanceConfig {
                name: "exit-a".into(),
                control_url: format!("http://{addr_1}"),
                token: "t1".into(),
                public_host: None,
                mesh_addr: None,
            },
            InstanceConfig {
                name: "exit-b".into(),
                control_url: format!("http://{addr_2}"),
                token: "t2".into(),
                public_host: None,
                mesh_addr: None,
            },
        ]),
        clusters: Arc::from(Vec::new()),
        refresh_ms: 5000,
    };

    let app = router(state);
    let res = app
        .clone()
        .oneshot(Request::get("/dashboard/api/clusters").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let json = json_body(&axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap());
    assert_eq!(json["clusters"].as_array().unwrap().len(), 1);
    assert_eq!(json["clusters"][0]["source"], "discovered");
    assert_eq!(json["clusters"][0]["name"], "auto-deadbe");
    assert_eq!(json["clusters"][0]["members"], json!(["exit-a", "exit-b"]));

    // Discovered cluster supports per-node user links fan-out
    let links_res = app
        .oneshot(
            Request::get("/dashboard/api/clusters/auto-deadbe/users/alice/access-keys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(links_res.status(), StatusCode::OK);
    let links_json =
        json_body(&axum::body::to_bytes(links_res.into_body(), 64 * 1024).await.unwrap());
    assert_eq!(links_json["mode"], "per_node");
    assert_eq!(links_json["nodes"].as_array().unwrap().len(), 2);
}
