//! Regression for the stable-source IPv6 preference (RFC 5014
//! `IPV6_PREFER_SRC_PUBLIC`): IPv4 must never be diverted onto the raw
//! socket2 path by the IPv6 preference, and an IPv6 connect must still
//! succeed whether the preference is active (raw path + best-effort
//! setsockopt) or auto-disabled (host rotation on → tokio fast path).
//!
//! Linux-only: the preference and its raw-path routing are gated to Linux.
#![cfg(target_os = "linux")]

use super::{connect_tcp_socket, prefer_public_raw_needed};

#[test]
fn ipv4_never_takes_prefer_raw_path() {
    // IPv4 is unaffected by the IPv6 source preference regardless of the
    // host's rotation state, so it always keeps tokio's fast path.
    assert!(!prefer_public_raw_needed("127.0.0.1:80".parse().unwrap()));
}

#[test]
fn ipv6_loopback_connect_succeeds() {
    // Whether the preference is on (raw socket2 path + best-effort
    // IPV6_PREFER_SRC_PUBLIC) or off (rotation active → fast path), a plain
    // IPv6 connect must still complete normally — the option is best-effort
    // and must never break dialing.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            // No IPv6 loopback in this environment — nothing to regress.
            Err(_) => return,
        };
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = connect_tcp_socket(addr, None)
            .await
            .expect("ipv6 connect must succeed");
        assert!(stream.peer_addr().is_ok());
        let _ = server.await;
    });
}
