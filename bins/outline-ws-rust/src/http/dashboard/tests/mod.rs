//! Listener-level tests: the credential gate as seen from the socket.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::*;
use crate::http::tests::streamed_request;

fn state_with_token(token: Option<&str>) -> DashboardState {
    DashboardState {
        refresh_interval_secs: 5,
        request_timeout_secs: 5,
        token: token.map(Arc::from),
        instances: Vec::new(),
    }
}

/// Drives one complete request against the dashboard listener and returns
/// `(status, body)`.
async fn request(state: DashboardState, head: String) -> (u16, String) {
    streamed_request(vec![head.into_bytes()], move |stream| async move {
        let _ = handle_connection(stream, state).await;
    })
    .await
}

fn head(method: &str, path: &str, credentials: Option<&str>) -> String {
    let authorization = match credentials {
        Some(value) => format!("Authorization: {value}\r\n"),
        None => String::new(),
    };
    format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{authorization}\
         Content-Length: 0\r\nConnection: close\r\n\r\n",
    )
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

/// The gate is only as good as the wiring that feeds it: a config token that
/// never reaches the state leaves every route open with no other symptom.
#[test]
fn state_carries_the_configured_token() {
    let config = DashboardConfig {
        listen: "127.0.0.1:9092".parse().unwrap(),
        refresh_interval_secs: 5,
        request_timeout_secs: 5,
        token: Some("secret".to_string()),
        instances: Vec::new(),
    };

    let state = DashboardState::from_config(config);

    assert_eq!(state.token.as_deref(), Some("secret"));
}

#[tokio::test]
async fn unauthenticated_listener_serves_the_ui_as_before() {
    let (status, _) = request(state_with_token(None), head("GET", "/dashboard", None)).await;

    assert_eq!(status, 200, "a dashboard without a token must keep working untouched");
}

#[tokio::test]
async fn configured_token_refuses_the_ui_without_credentials() {
    let (status, _) =
        request(state_with_token(Some("secret")), head("GET", "/dashboard", None)).await;

    assert_eq!(status, 401);
}

/// The mutating routes are the reason the gate exists: reaching them is
/// equivalent to holding every configured instance's control token.
#[tokio::test]
async fn configured_token_refuses_mutating_routes_without_credentials() {
    for (method, path) in [
        ("POST", "/dashboard/api/activate"),
        ("POST", "/dashboard/api/set_enabled"),
        ("POST", "/dashboard/api/reselect"),
        ("POST", "/dashboard/api/uplinks"),
        ("PATCH", "/dashboard/api/uplinks"),
        ("DELETE", "/dashboard/api/uplinks"),
        ("POST", "/dashboard/api/apply"),
    ] {
        let (status, _) = request(state_with_token(Some("secret")), head(method, path, None)).await;

        assert_eq!(status, 401, "{method} {path} must be refused without credentials");
    }
}

/// The gate runs before the router, so an unknown path is refused too — a route
/// added later cannot be reachable past it by construction.
#[tokio::test]
async fn configured_token_refuses_before_routing() {
    let (status, _) =
        request(state_with_token(Some("secret")), head("GET", "/dashboard/api/nope", None)).await;

    assert_eq!(status, 401, "the gate must precede route matching, not follow it");
}

#[tokio::test]
async fn configured_token_admits_both_credential_forms() {
    let bearer = request(
        state_with_token(Some("secret")),
        head("GET", "/dashboard", Some("Bearer secret")),
    )
    .await;
    let basic = request(
        state_with_token(Some("secret")),
        head("GET", "/dashboard", Some(&basic("admin", "secret"))),
    )
    .await;

    assert_eq!(bearer.0, 200);
    assert_eq!(basic.0, 200);
}

#[tokio::test]
async fn configured_token_refuses_wrong_credentials() {
    let (status, _) = request(
        state_with_token(Some("secret")),
        head("GET", "/dashboard", Some(&basic("admin", "nope"))),
    )
    .await;

    assert_eq!(status, 401);
}
