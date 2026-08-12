use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;

use super::*;

fn config() -> crate::config::UiConfig {
    crate::config::UiConfig {
        listen: "127.0.0.1:9000".parse().unwrap(),
        token: "s3cr3t".to_string(),
        request_timeout_secs: 5,
        refresh_interval_secs: 5,
        allowed_hosts: Vec::new(),
        ws: Vec::new(),
        ss: Vec::new(),
    }
}

fn authed(uri: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::AUTHORIZATION, "Bearer s3cr3t")
        .body(Body::empty())
        .unwrap()
}

/// The whole point of the extraction: the two dashboards share a port without
/// colliding, each seeing its own prefix.
#[tokio::test]
async fn both_trees_are_reachable_and_distinct() {
    let app = build_app(&config());

    let ws = app.clone().oneshot(authed("/ws/dashboard")).await.unwrap();
    assert_eq!(ws.status(), StatusCode::OK);
    let ws_body = axum::body::to_bytes(ws.into_body(), usize::MAX).await.unwrap();
    assert!(
        String::from_utf8(ws_body.to_vec())
            .unwrap()
            .contains(r#"API_BASE = "/ws""#)
    );

    let ss = app.oneshot(authed("/ss/dashboard")).await.unwrap();
    assert_eq!(ss.status(), StatusCode::OK);
    let ss_body = axum::body::to_bytes(ss.into_body(), usize::MAX).await.unwrap();
    assert!(
        String::from_utf8(ss_body.to_vec())
            .unwrap()
            .contains(r#"API_BASE = "/ss""#)
    );
}

#[tokio::test]
async fn the_index_lists_both() {
    let response = build_app(&config()).oneshot(authed("/")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("/ws/dashboard") && body.contains("/ss/dashboard"));
}

/// The gate must cover both trees, not just the root.
#[tokio::test]
async fn every_tree_is_behind_the_credential_gate() {
    let app = build_app(&config());

    for uri in ["/", "/ws/dashboard", "/ss/dashboard", "/ws/dashboard/api/instances"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(uri)
                    .header(header::HOST, "127.0.0.1:9000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "unguarded route: {uri}");
    }
}

/// Each tree serves its own logo path; a shared handler must still be reachable
/// under both prefixes.
#[tokio::test]
async fn both_logos_are_served() {
    let app = build_app(&config());

    let ws = app
        .clone()
        .oneshot(authed("/ws/dashboard/outline-logo.png"))
        .await
        .unwrap();
    assert_eq!(ws.status(), StatusCode::OK);

    let ss = app
        .oneshot(authed("/ss/dashboard/assets/outline-logo.png"))
        .await
        .unwrap();
    assert_eq!(ss.status(), StatusCode::OK);
}
