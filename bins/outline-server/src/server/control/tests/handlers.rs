use super::*;

#[test]
fn create_request_rejects_unknown_fields() {
    // Stale clients sending removed per-user path fields like `ws_path_tcp`
    // must get a deserialization error (400), not silent-ignore.
    let json = r#"
    {
        "id": "test-user",
        "password": "secret",
        "ws_path_tcp": "/x"
    }
    "#;

    let result: Result<CreateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "CreateRequest must reject unknown field 'ws_path_tcp', got {:?}",
        result
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown field"),
        "error message must mention unknown field: {}",
        err_msg
    );
}

#[test]
fn create_request_accepts_valid_fields() {
    let json = r#"
    {
        "id": "test-user",
        "password": "secret",
        "method": "2022-blake3-aes-256-gcm"
    }
    "#;

    let result: Result<CreateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_ok(),
        "CreateRequest must accept valid fields, got error: {:?}",
        result
    );
    let req = result.unwrap();
    assert_eq!(req.id, "test-user");
    assert_eq!(req.password, Some("secret".to_string()));
}

#[test]
fn update_request_rejects_unknown_fields() {
    // Stale clients sending removed per-user path fields must fail.
    let json = r#"
    {
        "password": "new-secret",
        "ws_path_tcp": "/x"
    }
    "#;

    let result: Result<UpdateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "UpdateRequest must reject unknown field 'ws_path_tcp', got {:?}",
        result
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unknown field"),
        "error message must mention unknown field: {}",
        err_msg
    );
}

#[test]
fn update_request_accepts_valid_fields() {
    let json = r#"
    {
        "password": "new-secret",
        "enabled": true
    }
    "#;

    let result: Result<UpdateRequest, _> = serde_json::from_str(json);
    assert!(
        result.is_ok(),
        "UpdateRequest must accept valid fields, got error: {:?}",
        result
    );
    let req = result.unwrap();
    assert!(matches!(req.password, FieldPatch::Set(_)));
    assert_eq!(req.enabled, Some(true));
}

#[test]
fn server_config_patch_deserializes_extended_fields() {
    let json = r#"
    {
        "tuning_profile": "medium",
        "padding": {
            "min_bytes": 10,
            "max_bytes": 200,
            "cover": true,
            "throttle_detect_enabled": true
        },
        "http_fallback": {
            "backend": "127.0.0.1:8080",
            "proxy_protocol": "v2",
            "backend_proto": "h1"
        },
        "server": {
            "h3_initial_mtu": 1350,
            "h3_mtu_first_probe": 1452
        },
        "outbound": {
            "ipv6_prefix_interface": "eth0",
            "ipv6_refresh_secs": 60
        },
        "sni_fallback": {
            "match_sni": ["*.fleet.example"],
            "allow_no_sni": false,
            "max_client_hello_bytes": 4096,
            "backends": [
                {
                    "backend": "127.0.0.1:11443",
                    "proxy_protocol": "v1"
                }
            ]
        },
        "endpoints": [
            {
                "path": "/ss-ws",
                "padded": true
            }
        ]
    }
    "#;

    let patch: ServerConfigPatch =
        serde_json::from_str(json).expect("deserialize ServerConfigPatch");
    assert_eq!(patch.tuning_profile, FieldPatch::Set(Some("medium".to_string())));
    let FieldPatch::Set(Some(pad)) = patch.padding else {
        panic!("expected padding patch");
    };
    assert_eq!(pad.min_bytes, FieldPatch::Set(Some(10)));
    assert_eq!(pad.max_bytes, FieldPatch::Set(Some(200)));
    assert_eq!(pad.cover, FieldPatch::Set(Some(true)));
    assert_eq!(pad.throttle_detect_enabled, FieldPatch::Set(Some(true)));
    let FieldPatch::Set(Some(hf)) = patch.http_fallback else {
        panic!("expected http_fallback patch");
    };
    assert_eq!(hf.backend, FieldPatch::Set(Some("127.0.0.1:8080".to_string())));
    assert_eq!(hf.proxy_protocol, FieldPatch::Set(Some("v2".to_string())));
    assert_eq!(hf.backend_proto, FieldPatch::Set(Some("h1".to_string())));
    let FieldPatch::Set(Some(srv)) = patch.server else {
        panic!("expected server patch");
    };
    assert_eq!(srv.h3_initial_mtu, FieldPatch::Set(Some(1350)));
    assert_eq!(srv.h3_mtu_first_probe, FieldPatch::Set(Some(1452)));
    let FieldPatch::Set(Some(out)) = patch.outbound else {
        panic!("expected outbound patch");
    };
    assert_eq!(out.ipv6_prefix_interface, FieldPatch::Set(Some("eth0".to_string())));
    assert_eq!(out.ipv6_refresh_secs, FieldPatch::Set(Some(60)));
    let FieldPatch::Set(Some(sf)) = patch.sni_fallback else {
        panic!("expected sni_fallback patch");
    };
    assert_eq!(sf.match_sni, FieldPatch::Set(Some(vec!["*.fleet.example".to_string()])));
    assert_eq!(sf.allow_no_sni, FieldPatch::Set(Some(false)));
    assert_eq!(sf.max_client_hello_bytes, FieldPatch::Set(Some(4096)));
    let FieldPatch::Set(Some(backends)) = sf.backends else {
        panic!("expected sni backends");
    };
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0].backend, "127.0.0.1:11443");
    assert_eq!(backends[0].proxy_protocol.as_deref(), Some("v1"));
    let FieldPatch::Set(Some(endpoints)) = patch.endpoints else {
        panic!("expected endpoints patch");
    };
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].path, "/ss-ws");
    assert!(endpoints[0].padded);
}

#[test]
fn server_config_patch_distinguishes_missing_and_null_and_tracks_restart_scope() {
    let json = r#"
    {
        "access_keys": {
            "public_scheme": "wss",
            "url_base": null,
            "nodes": ["relay-a.fleet.example", "relay-b.fleet.example"]
        }
    }
    "#;
    let patch: ServerConfigPatch =
        serde_json::from_str(json).expect("deserialize access_keys-only patch");
    assert!(!patch.touches_runtime_settings());
    let FieldPatch::Set(Some(ak)) = patch.access_keys else {
        panic!("expected access_keys patch");
    };
    assert_eq!(ak.public_scheme, FieldPatch::Set(Some("wss".to_string())));
    assert_eq!(ak.url_base, FieldPatch::Set(None));
    assert_eq!(
        ak.nodes,
        FieldPatch::Set(Some(vec![
            "relay-a.fleet.example".to_string(),
            "relay-b.fleet.example".to_string()
        ]))
    );
    assert!(patch.tuning_profile.is_missing());
}

#[tokio::test]
async fn get_and_patch_config_track_restart_pending_and_psk_fingerprint() {
    use axum::{Json, extract::State, http::StatusCode};

    let tmp_dir = std::env::temp_dir().join(format!(
        "outline-handlers-cfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let cfg_path = tmp_dir.join("config.toml");
    let psk_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let initial = format!(
        r#"
[server]
listen = "127.0.0.1:443"
cert_path = "cert.pem"
key_path = "key.pem"

[server.h3]
listen = "127.0.0.1:443"

[cluster]
enabled = true
shard_id = 0
cluster_psk = "{psk_b64}"
mesh_listen = "127.0.0.1:9443"

[[endpoint]]
path = "/ws"
kind = "ws_ss"
padded = false

[[users]]
id = "alice"
password = "pw-alice"
"#
    );
    std::fs::write(&cfg_path, &initial).unwrap();

    let mut cfg = crate::config::parse_and_validate(&initial).unwrap();
    cfg.config_path = Some(cfg_path.clone());
    let cfg = Arc::new(cfg);
    let manager = Arc::new(crate::server::control::manager::manager_for((*cfg).clone()));
    let state = ControlState {
        manager,
        config: cfg,
        token: Arc::from("tok"),
        access_keys: None,
    };

    // Initially disk matches running config -> restart_pending = false.
    let resp = get_config(State(state.clone())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["restart_pending"], false);
    assert_eq!(json["endpoints"][0]["kind"], "ws_ss");
    let fp = json["cluster"]["psk_fingerprint"]
        .as_str()
        .expect("psk_fingerprint present");
    assert_eq!(fp.len(), 12);
    assert_eq!(json["cluster"]["cluster_psk"], "********");

    // Patching only access_keys -> requires_restart = false & restart_pending stays false.
    let ak_patch: ServerConfigPatch = serde_json::from_value(serde_json::json!({
        "access_keys": {
            "public_host": "edge.fleet.example",
            "public_scheme": "wss",
            "nodes": ["relay-a.fleet.example"]
        }
    }))
    .unwrap();
    let res = patch_config(State(state.clone()), Json(ak_patch)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let res_json: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(res_json["requires_restart"], false);

    let after_ak: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(get_config(State(state.clone())).await.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(after_ak["restart_pending"], false);
    assert_eq!(after_ak["access_keys"]["nodes"][0], "relay-a.fleet.example");

    // Patching endpoints with duplicate path -> 400 Bad Request.
    let dup_ep_patch: ServerConfigPatch = serde_json::from_value(serde_json::json!({
        "endpoints": [
            { "path": "/dup", "kind": "ws_ss", "padded": false },
            { "path": "/dup", "kind": "xhttp_ss", "padded": false }
        ]
    }))
    .unwrap();
    let bad = patch_config(State(state.clone()), Json(dup_ep_patch)).await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);

    // Patching runtime endpoint -> requires_restart = true & restart_pending = true.
    let ep_patch: ServerConfigPatch = serde_json::from_value(serde_json::json!({
        "endpoints": [
            { "path": "/ws", "kind": "ws_ss", "padded": false },
            { "path": "/vless", "kind": "xhttp_vless", "padded": true }
        ]
    }))
    .unwrap();
    let res2 = patch_config(State(state.clone()), Json(ep_patch)).await;
    assert_eq!(res2.status(), StatusCode::OK);
    let res2_json: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(res2.into_body(), 64 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(res2_json["requires_restart"], true);

    let after_ep: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(get_config(State(state)).await.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(after_ep["restart_pending"], true);
    assert_eq!(after_ep["endpoints"].as_array().unwrap().len(), 2);

    let _ = std::fs::remove_dir_all(tmp_dir);
}
