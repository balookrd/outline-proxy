use std::time::Duration;

use axum::{Router, routing::any};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::{
    TestHttpHeaderReadTimeout, TlsHandshakeFailReason, classify_tls_handshake_error,
    serve_listener, serve_metrics_listener,
};
use crate::server::shutdown::ShutdownSignal;

#[test]
fn tls_handshake_unexpected_eof_is_closed_early() {
    let error = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
    assert!(matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::ClosedEarly
    ));
}

#[test]
fn tls_handshake_protocol_failure_is_not_closed_early() {
    let error = std::io::Error::other("received corrupt message");
    assert!(!matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::ClosedEarly
    ));
}

#[test]
fn no_cert_chain_resolved_is_classified() {
    // rustls wraps `Error::General(...)` with `io::ErrorKind::InvalidData`
    // when `ResolvesServerCert::resolve` returns `None`. Verify the
    // classifier still picks it up — if upstream rustls rephrases the
    // string this test fails loudly and the bucket falls back to
    // `protocol_error` until the matcher is updated.
    let inner = rustls::Error::General("no server certificate chain resolved".to_owned());
    let error = std::io::Error::new(std::io::ErrorKind::InvalidData, inner);
    assert!(matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::NoCertChain
    ));
}

#[test]
fn other_invalid_data_is_protocol_error() {
    let inner = rustls::Error::General("some other rustls failure".to_owned());
    let error = std::io::Error::new(std::io::ErrorKind::InvalidData, inner);
    assert!(matches!(
        classify_tls_handshake_error(&error),
        TlsHandshakeFailReason::ProtocolError
    ));
}

/// A peer that connects to the plain listener and then sends nothing must not
/// pin its connection task / semaphore permit indefinitely: hyper's protocol
/// sniff has no timeout of its own, so the accept loop's first-byte peek
/// deadline has to close the silent peer. With the pre-auth budget squeezed to
/// 200 ms the server-side close (EOF) must arrive well inside the 2 s guard.
#[tokio::test]
async fn plain_listener_drops_silent_preauth_peer() {
    let _timeout = TestHttpHeaderReadTimeout::set(Duration::from_millis(200));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(any(|| async { "ok" }));
    let server = tokio::spawn(serve_listener(listener, app, ShutdownSignal::never()));

    // Connect and stay silent — never send a byte.
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;

    assert!(read.is_ok(), "server did not drop the silent peer before the guard fired");
    assert_eq!(
        read.unwrap().unwrap(),
        0,
        "expected an EOF from the server-side close, not response bytes",
    );

    server.abort();
}

/// A peer that opens an HTTP/1 request and then stalls mid-headers (never
/// sending the terminating CRLF) must be closed by hyper's `header_read_timeout`
/// rather than holding its task forever. We only assert the connection is torn
/// down inside the guard — whether hyper answers with a 408 first or just drops
/// the socket is an implementation detail we drain past.
#[tokio::test]
async fn plain_listener_drops_slow_header_peer() {
    let _timeout = TestHttpHeaderReadTimeout::set(Duration::from_millis(200));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(any(|| async { "ok" }));
    let server = tokio::spawn(serve_listener(listener, app, ShutdownSignal::never()));

    let mut client = TcpStream::connect(addr).await.unwrap();
    // A first byte arrives (so the peek passes), but the header block is never
    // terminated. `header_read_timeout` must fire.
    client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut buf = [0u8; 1024];
        loop {
            match client.read(&mut buf).await {
                Ok(0) => break,    // server closed the connection
                Ok(_) => continue, // drain any 408 bytes hyper may send first
                Err(_) => break,
            }
        }
    })
    .await;

    assert!(closed.is_ok(), "server did not close the slow-header peer within the guard");

    server.abort();
}

/// The metrics endpoint shares the plain-HTTP accept loop, so it must inherit
/// the same pre-auth slowloris protection: a peer that connects and stays
/// silent is dropped once the first-byte peek deadline elapses, rather than
/// pinning a task/permit forever. Guards against a regression that would put
/// the metrics listener back on an unbounded `axum::serve`.
#[tokio::test]
async fn metrics_listener_drops_silent_preauth_peer() {
    let _timeout = TestHttpHeaderReadTimeout::set(Duration::from_millis(200));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(any(|| async { "metrics" }));
    let server = tokio::spawn(serve_metrics_listener(listener, app, ShutdownSignal::never()));

    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;

    assert!(
        read.is_ok(),
        "metrics listener did not drop the silent peer before the guard fired"
    );
    assert_eq!(read.unwrap().unwrap(), 0, "expected an EOF from the server-side close");

    server.abort();
}
