use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::super::control_pool::ControlPool;
use super::*;

#[test]
fn instance_uri_preserves_base_path_prefix() {
    let uri = instance_uri("http://127.0.0.1:7001/admin", "/control/users").unwrap();
    assert_eq!(uri.to_string(), "http://127.0.0.1:7001/admin/control/users");
}

#[test]
fn instance_uri_supports_https() {
    let uri = instance_uri("https://edge.example.com:7443/admin", "/control/users").unwrap();
    assert_eq!(uri.to_string(), "https://edge.example.com:7443/admin/control/users");
}

fn get_request() -> hyper::Request<Full<Bytes>> {
    hyper::Request::builder()
        .method(Method::GET)
        .uri("/control/users")
        .header(header::HOST, "control.test")
        .body(Full::new(Bytes::new()))
        .expect("valid request")
}

/// Serves one HTTP/1 response with `body_len` bytes of payload on `io`, after
/// draining the request head.
async fn serve_body(mut io: tokio::io::DuplexStream, body_len: usize) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while io.read_exact(&mut byte).await.is_ok() {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
    );
    if io.write_all(header.as_bytes()).await.is_err() {
        return;
    }
    let chunk = vec![b'x'; 4096];
    let mut left = body_len;
    while left > 0 {
        let n = left.min(chunk.len());
        if io.write_all(&chunk[..n]).await.is_err() {
            return;
        }
        left -= n;
    }
    let _ = io.flush().await;
}

#[tokio::test]
async fn exchange_rejects_a_control_response_body_past_the_cap() {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let server = tokio::spawn(serve_body(server_io, 64 * 1024));

    let mut sender = handshake(client_io).await.expect("handshake");
    let error = exchange(&mut sender, get_request(), 8 * 1024)
        .await
        .expect_err("an oversized control response must not be buffered");
    assert!(
        format!("{error:#}").contains("control response body"),
        "unexpected error: {error:#}",
    );

    server.abort();
}

fn test_state(instance: &DashboardInstanceConfig) -> DashboardState {
    DashboardState {
        request_timeout_secs: 5,
        refresh_interval_secs: 10,
        instances: Arc::from(vec![instance.clone()]),
        tls_connector: crate::server::dashboard::tls::connector(),
        token: None,
        control_pool: Arc::new(ControlPool::new(2, Duration::from_secs(30))),
    }
}

/// Answers every request on `sock` with a small JSON body, keeping the
/// connection alive — a stand-in for the control API.
async fn serve_keep_alive(mut sock: TcpStream) {
    let mut pending = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let Ok(read) = sock.read(&mut buf).await else { return };
        if read == 0 {
            return;
        }
        pending.extend_from_slice(&buf[..read]);
        while let Some(end) = pending
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|start| start + 4)
        {
            pending.drain(..end);
            let response =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
            if sock.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
    }
}

/// A control-API stand-in that counts how many TCP connections it accepted.
async fn spawn_control_stub() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let handle = tokio::spawn({
        let accepted = Arc::clone(&accepted);
        async move {
            while let Ok((sock, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_keep_alive(sock));
            }
        }
    });
    (format!("http://{addr}"), accepted, handle)
}

#[tokio::test]
async fn a_second_read_request_rides_the_pooled_connection() {
    let (control_url, accepted, server) = spawn_control_stub().await;
    let instance = DashboardInstanceConfig {
        name: "edge".into(),
        control_url,
        token: "token".into(),
    };
    let state = test_state(&instance);

    for _ in 0..2 {
        let (status, body) =
            send_control_request(&state, &instance, Method::GET, "/control/users", None)
                .await
                .expect("control request");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), b"{}");
    }

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "the second read must reuse the parked connection instead of dialing again",
    );
    server.abort();
}

#[tokio::test]
async fn mutating_requests_do_not_reuse_a_pooled_connection() {
    let (control_url, accepted, server) = spawn_control_stub().await;
    let instance = DashboardInstanceConfig {
        name: "edge".into(),
        control_url,
        token: "token".into(),
    };
    let state = test_state(&instance);

    send_control_request(&state, &instance, Method::GET, "/control/users", None)
        .await
        .expect("control request");
    send_control_request(&state, &instance, Method::POST, "/control/users", Some(b"{}".to_vec()))
        .await
        .expect("control request");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "a mutation must dial fresh: replaying it on a socket the upstream closed \
         underneath us could double-apply it",
    );
    server.abort();
}

#[tokio::test]
async fn exchange_returns_a_control_response_within_the_cap() {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let server = tokio::spawn(serve_body(server_io, 4 * 1024));

    let mut sender = handshake(client_io).await.expect("handshake");
    let (status, body) = exchange(&mut sender, get_request(), 8 * 1024)
        .await
        .expect("a response within the cap must pass through");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 4 * 1024);

    server.abort();
}
