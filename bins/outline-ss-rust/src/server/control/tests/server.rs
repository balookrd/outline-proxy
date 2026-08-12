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
