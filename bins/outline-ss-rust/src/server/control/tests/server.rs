use super::*;

#[test]
fn bearer_token_parsing() {
    let ok = HeaderValue::from_static("Bearer secret");
    assert!(bearer_token_matches(&ok, "secret"));
    let wrong = HeaderValue::from_static("Bearer bad");
    assert!(!bearer_token_matches(&wrong, "secret"));
    let basic = HeaderValue::from_static("Basic secret");
    assert!(!bearer_token_matches(&basic, "secret"));
}

/// The control listener now runs on the shared plain-HTTP accept loop
/// (`serve_control_router` -> `serve_plain_listener`), so a peer that connects
/// and stays silent must be dropped by the pre-auth peek deadline rather than
/// pinning a task/permit — the bearer-token gate never gets a chance to run.
/// Guards against a regression that would put it back on unbounded
/// `axum::serve`.
#[tokio::test]
async fn control_listener_drops_silent_preauth_peer() {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    let _timeout = crate::server::bootstrap::TestHttpHeaderReadTimeout::set(
        std::time::Duration::from_millis(200),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().fallback(any(not_found));
    let server = tokio::spawn(serve_control_router(listener, router, ShutdownSignal::never()));

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf)).await;

    assert!(
        read.is_ok(),
        "control listener did not drop the silent peer before the guard fired"
    );
    assert_eq!(read.unwrap().unwrap(), 0, "expected an EOF from the server-side close");

    server.abort();
}

/// A control state over a manager with no users and the default paths — enough
/// to exercise routing and the bearer gate. `test_manager()` is synchronous, so
/// this needs no `async`.
fn test_control_state() -> ControlState {
    ControlState {
        manager: Arc::new(crate::server::control::manager::test_manager()),
        token: Arc::from("test-token"),
    }
}

/// `/control/defaults` must sit behind the same bearer gate as every other
/// control route: it is read-only, but the control listener as a whole is
/// authenticated, and an unauthenticated 200 here would be a policy hole.
/// Drives a real request through the same router `run()` builds.
#[tokio::test]
async fn defaults_route_requires_the_bearer_token_and_answers_json() {
    use tower::ServiceExt; // for `oneshot`

    let state = test_control_state();
    let router = Router::new()
        .route("/control/defaults", get(get_defaults))
        .fallback(any(not_found))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer_token))
        .with_state(state);

    // No token -> rejected by the gate, never reaches the handler.
    let unauthorized = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/control/defaults")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // With the token -> 200 with the defaults payload.
    let authorized = router
        .oneshot(
            Request::builder()
                .uri("/control/defaults")
                .header(AUTHORIZATION, "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    let body = axum::body::to_bytes(authorized.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["method"].is_string(), "method must be present as a string");
    assert!(json.get("password").is_none(), "defaults must never carry secrets");
    assert!(json.get("vless_id").is_none(), "defaults must never carry secrets");
}
