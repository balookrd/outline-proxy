use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::*;

fn state() -> SsState {
    SsState {
        backend: std::sync::Arc::new(crate::backend::Backend::new(5)),
        instances: std::sync::Arc::from(Vec::new()),
        refresh_ms: 5000,
    }
}

#[tokio::test]
async fn lists_configured_instances() {
    let response = router(state())
        .oneshot(Request::get("/dashboard/api/instances").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn users_for_an_unknown_instance_is_reported() {
    let response = router(state())
        .oneshot(
            Request::get("/dashboard/api/users?instance=nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
