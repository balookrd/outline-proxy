use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use axum::{Router, middleware};
use tower::ServiceExt as _;

use super::*;

fn app(allowed: &[&str]) -> Router {
    let policy = OriginPolicy::new(
        "127.0.0.1:9000".parse().unwrap(),
        &allowed.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    Router::new()
        .route("/probe", get(|| async { "ok" }))
        .route("/mutate", post(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(policy, enforce_origin))
}

async fn status(app: Router, request: Request<Body>) -> StatusCode {
    app.oneshot(request).await.unwrap().status()
}

/// curl sends no Origin at all. Refusing that would break every scripted client
/// while stopping no browser attack, because a browser always sends one.
#[tokio::test]
async fn request_without_origin_is_allowed() {
    let request = Request::get("/probe")
        .header(header::HOST, "127.0.0.1:9000")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::OK);
}

#[tokio::test]
async fn foreign_origin_on_a_mutation_is_refused() {
    let request = Request::post("/mutate")
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn matching_origin_on_a_mutation_is_allowed() {
    let request = Request::post("/mutate")
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::ORIGIN, "http://127.0.0.1:9000")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::OK);
}

/// Behind an ingress the browser's Host is the public name, not the pod's
/// listen address, so that name has to be configurable or the UI 403s itself.
#[tokio::test]
async fn configured_allowed_host_is_accepted() {
    let request = Request::post("/mutate")
        .header(header::HOST, "ui.k3s.beerloga.su")
        .header(header::ORIGIN, "https://ui.k3s.beerloga.su")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&["ui.k3s.beerloga.su"]), request).await, StatusCode::OK);
}

#[tokio::test]
async fn unknown_host_is_refused() {
    let request = Request::get("/probe")
        .header(header::HOST, "attacker.example")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::FORBIDDEN);
}

/// The third check: a body-bearing method without a JSON content type is what a
/// cross-origin form post looks like, and those never carry `Origin` to be
/// caught by the check above.
#[tokio::test]
async fn mutation_without_json_content_type_is_refused() {
    let request = Request::post("/mutate")
        .header(header::HOST, "127.0.0.1:9000")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
