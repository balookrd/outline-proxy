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
            "h3_initial_mtu": 1350
        },
        "outbound": {
            "ipv6_prefix_interface": "eth0",
            "ipv6_refresh_secs": 60
        },
        "sni_fallback": {
            "match_sni": ["*.beerloga.su"],
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
    assert_eq!(patch.tuning_profile.as_deref(), Some("medium"));
    let pad = patch.padding.expect("padding patch");
    assert_eq!(pad.min_bytes, Some(10));
    assert_eq!(pad.max_bytes, Some(200));
    assert_eq!(pad.cover, Some(true));
    assert_eq!(pad.throttle_detect_enabled, Some(true));
    let hf = patch.http_fallback.expect("http_fallback patch");
    assert_eq!(hf.backend.as_deref(), Some("127.0.0.1:8080"));
    assert_eq!(hf.proxy_protocol.as_deref(), Some("v2"));
    assert_eq!(hf.backend_proto.as_deref(), Some("h1"));
    let srv = patch.server.expect("server patch");
    assert_eq!(srv.h3_initial_mtu, Some(1350));
    let out = patch.outbound.expect("outbound patch");
    assert_eq!(out.ipv6_prefix_interface.as_deref(), Some("eth0"));
    assert_eq!(out.ipv6_refresh_secs, Some(60));
    let sf = patch.sni_fallback.expect("sni_fallback patch");
    assert_eq!(sf.match_sni.as_deref(), Some(&["*.beerloga.su".to_string()][..]));
    assert_eq!(sf.allow_no_sni, Some(false));
    assert_eq!(sf.max_client_hello_bytes, Some(4096));
    let backends = sf.backends.expect("sni backends");
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0].backend, "127.0.0.1:11443");
    assert_eq!(backends[0].proxy_protocol.as_deref(), Some("v1"));
    let endpoints = patch.endpoints.expect("endpoints patch");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].path, "/ss-ws");
    assert!(endpoints[0].padded);
}
