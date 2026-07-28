use std::io;

use anyhow::anyhow;

use super::is_client_disconnect;

/// ~3 events a minute on the metrics port came from a monitoring poller that
/// opened a socket and went away before sending headers. That is the client's
/// behaviour, not a listener fault, so it must not reach `warn!`.
#[test]
fn header_read_timeout_is_a_client_disconnect() {
    let error = anyhow!("error serving connection").context("read header from client timeout");
    assert!(is_client_disconnect(&error));
}

/// The same for the other shapes of "the peer hung up", whether hyper renders
/// them as text or they arrive as a typed io error somewhere in the chain.
#[test]
fn peer_hangups_are_client_disconnects() {
    let closed_early = anyhow!("connection closed before message completed");
    assert!(is_client_disconnect(&closed_early));

    let reset = anyhow::Error::new(io::Error::new(io::ErrorKind::ConnectionReset, "reset"))
        .context("serving metrics request");
    assert!(is_client_disconnect(&reset));

    let broken_pipe = anyhow::Error::new(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe"));
    assert!(is_client_disconnect(&broken_pipe));
}

/// Real listener failures must keep their `warn!` — the demotion above must not
/// swallow a handler that genuinely failed to serve a request.
#[test]
fn real_failures_are_not_client_disconnects() {
    assert!(!is_client_disconnect(&anyhow!("failed to render metrics snapshot")));
    assert!(!is_client_disconnect(&anyhow!("invalid bearer token")));
    let permission = anyhow::Error::new(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
    assert!(!is_client_disconnect(&permission));
}
