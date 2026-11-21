use super::*;

/// A user id lands in the control URL's path. Without encoding, an id like
/// `x/../../control/apply` would reach a different endpoint entirely.
#[test]
fn path_segment_encoding_blocks_traversal() {
    assert_eq!(encode_path_segment("plain-id_1"), "plain-id_1");
    assert_eq!(encode_path_segment("a/b"), "a%2Fb");
    assert_eq!(encode_path_segment("x?y=1"), "x%3Fy%3D1");
    assert_eq!(encode_path_segment("../../etc"), "%2E%2E%2F%2E%2E%2Fetc");
    assert_eq!(encode_path_segment(".."), "%2E%2E");
    assert_eq!(encode_path_segment("."), "%2E");
}

#[test]
fn user_id_validation_rejects_dot_segments_and_slashes() {
    assert!(!is_valid_user_id(""));
    assert!(!is_valid_user_id("   "));
    assert!(!is_valid_user_id("."));
    assert!(!is_valid_user_id(".."));
    assert!(!is_valid_user_id("foo/bar"));
    assert!(!is_valid_user_id("foo\\bar"));
    assert!(is_valid_user_id("valid-user-123"));
    assert!(is_valid_user_id("user.name"));
}

#[tokio::test]
async fn list_instances_includes_clusters_and_instance_metadata() {
    let state = crate::ss::SsState {
        backend: std::sync::Arc::new(crate::backend::Backend::new(5)),
        instances: std::sync::Arc::from(vec![crate::config::InstanceConfig {
            name: "relay-a".to_string(),
            control_url: "http://127.0.0.1:9191".to_string(),
            token: "tok".to_string(),
            public_host: Some("relay-a.fleet.example".to_string()),
            mesh_addr: Some("198.51.100.10:9443".to_string()),
        }]),
        clusters: std::sync::Arc::from(vec![crate::config::ClusterConfig {
            name: "cloud".to_string(),
            members: vec!["relay-a".to_string()],
            subscription_nodes: vec!["relay-a.fleet.example".to_string()],
        }]),
        refresh_ms: 5000,
    };

    let resp = list_instances(axum::extract::State(state)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["instances"][0]["cluster"], "cloud");
    assert_eq!(json["instances"][0]["public_host"], "relay-a.fleet.example");
    assert_eq!(json["clusters"][0]["name"], "cloud");
    assert_eq!(json["clusters"][0]["source"], "config");
    assert_eq!(json["clusters"][0]["subscription_nodes"][0], "relay-a.fleet.example");
}
