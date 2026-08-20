use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Router, middleware};
use tower::ServiceExt as _;

// `base64::Engine` (needed for `.encode()`) is already in scope via `super::*`
// from the parent module, so no local `use base64::Engine as _` here.
use super::*;

fn app(token: &str) -> Router {
    let state = AuthState { token: std::sync::Arc::from(token) };
    Router::new()
        .route("/probe", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(state, require_auth))
}

async fn status_for(request: Request<Body>) -> StatusCode {
    app("s3cr3t").oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn no_credentials_is_401_with_a_browser_prompt() {
    let response = app("s3cr3t")
        .oneshot(Request::get("/probe").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Without this a browser shows a bare 401 page and the operator has no way
    // to enter the token at all.
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn correct_bearer_passes() {
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, "Bearer s3cr3t")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::OK);
}

#[tokio::test]
async fn correct_basic_password_passes() {
    let encoded = base64::engine::general_purpose::STANDARD.encode("admin:s3cr3t");
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, format!("Basic {encoded}"))
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::OK);
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, "Bearer wrong")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::UNAUTHORIZED);
}

/// A prefix of the real token must not pass; comparison is over the whole value.
#[tokio::test]
async fn token_prefix_is_rejected() {
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, "Bearer s3cr")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::UNAUTHORIZED);
}
