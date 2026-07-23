use hyper_util::rt::TokioIo;

use super::*;

/// Builds a live HTTP/1 sender over an in-memory duplex. The server half is
/// returned so the caller can keep the connection open for the test.
async fn live_sender() -> (SendRequest<Full<Bytes>>, tokio::io::DuplexStream) {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, server_io)
}

#[tokio::test]
async fn parks_and_hands_back_a_connection() {
    let pool = ControlPool::new(2, Duration::from_secs(30));
    let (sender, _server) = live_sender().await;

    pool.put("http://control.test:7001", sender);
    assert!(pool.take("http://control.test:7001").is_some());
    assert!(
        pool.take("http://control.test:7001").is_none(),
        "a taken connection must not be handed out twice",
    );
}

#[tokio::test]
async fn keeps_at_most_max_idle_per_target() {
    let pool = ControlPool::new(2, Duration::from_secs(30));
    let mut servers = Vec::new();
    for _ in 0..3 {
        let (sender, server) = live_sender().await;
        servers.push(server);
        pool.put("http://control.test:7001", sender);
    }

    assert!(pool.take("http://control.test:7001").is_some());
    assert!(pool.take("http://control.test:7001").is_some());
    assert!(
        pool.take("http://control.test:7001").is_none(),
        "the pool must not park more than max_idle_per_target connections",
    );
}

#[tokio::test]
async fn does_not_hand_out_connections_past_the_idle_ttl() {
    let pool = ControlPool::new(2, Duration::ZERO);
    let (sender, _server) = live_sender().await;

    pool.put("http://control.test:7001", sender);
    assert!(
        pool.take("http://control.test:7001").is_none(),
        "a connection older than idle_ttl must be discarded, not reused",
    );
}

#[tokio::test]
async fn buckets_are_keyed_by_target() {
    let pool = ControlPool::new(2, Duration::from_secs(30));
    let (sender, _server) = live_sender().await;

    pool.put("http://control.test:7001", sender);
    assert!(
        pool.take("http://other.test:7001").is_none(),
        "a connection must never be handed to a different upstream",
    );
}
