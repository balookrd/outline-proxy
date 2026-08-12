use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::*;

fn state() -> WsState {
    WsState {
        backend: std::sync::Arc::new(crate::backend::Backend::new(5)),
        instances: std::sync::Arc::from(Vec::new()),
        refresh_ms: 5000,
    }
}

#[tokio::test]
async fn serves_the_dashboard_page_with_its_prefix() {
    let response = router(state())
        .oneshot(Request::get("/dashboard").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains(r#"const API_BASE = "/ws""#), "prefix not substituted");
    assert!(!body.contains("__BASE__"), "placeholder survived into the response");
}

#[tokio::test]
async fn serves_the_uplinks_page() {
    let response = router(state())
        .oneshot(Request::get("/dashboard/uplinks").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn lists_configured_instances() {
    let response = router(state())
        .oneshot(Request::get("/dashboard/api/instances").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// A request naming an instance that is not configured must say so, not fall
/// through to a generic 404 the JS renders as an empty page.
#[tokio::test]
async fn topology_for_an_unknown_instance_is_reported() {
    let response = router(state())
        .oneshot(
            Request::get("/dashboard/api/topology?instance=nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8(body.to_vec()).unwrap().contains("unknown instance"));
}
