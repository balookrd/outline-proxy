use axum::{Router, routing::any};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use super::serve_dashboard_router;
use crate::server::bootstrap::TestHttpHeaderReadTimeout;
use crate::server::shutdown::ShutdownSignal;

/// The dashboard listener now runs on the shared plain-HTTP accept loop
/// (`serve_dashboard_router` -> `serve_plain_listener`), so a peer that connects
/// and stays silent must be dropped by the pre-auth peek deadline rather than
/// pinning a task/permit — the origin guard / token gate never gets a chance to
/// run. Guards against a regression that would put it back on unbounded
/// `axum::serve`.
#[tokio::test]
async fn dashboard_listener_drops_silent_preauth_peer() {
    let _timeout = TestHttpHeaderReadTimeout::set(std::time::Duration::from_millis(200));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().fallback(any(|| async { "dashboard" }));
    let server = tokio::spawn(serve_dashboard_router(listener, router, ShutdownSignal::never()));

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf)).await;

    assert!(
        read.is_ok(),
        "dashboard listener did not drop the silent peer before the guard fired"
    );
    assert_eq!(read.unwrap().unwrap(), 0, "expected an EOF from the server-side close");

    server.abort();
}
