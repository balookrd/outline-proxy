use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use shadowsocks_crypto::SHADOWSOCKS_MAX_PAYLOAD;
use outline_metrics as metrics;
use socks5_proto::{SOCKS_STATUS_SUCCESS, TargetAddr, send_reply, socket_addr_to_target};
use super::session::POST_CLIENT_EOF_DOWNSTREAM_TIMEOUT;

// Direct TCP sessions (bypass-routed) are held open as long as both sides
// keep the connection alive.  Applications such as DNS-over-HTTPS/TLS clients
// open a new TCP+TLS connection per query burst and then abandon the old one
// without sending FIN — the HTTP/2 server keeps its side open.  Without a
// bound these accumulate indefinitely.
//
// DIRECT_IDLE_TIMEOUT closes a direct session once BOTH directions have been
// silent for this long.  Activity in either direction resets the timer.
// 2 minutes is generous for DoH/DoT (a silent connection is always abandoned)
// while still being safe for periodic-push traffic (Telegram, FCM, etc. send
// heartbeats every 30–60 s so their connections will never hit this timeout).
pub(super) const DIRECT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) async fn handle_tcp_direct(
    mut client: TcpStream,
    target: TargetAddr,
    fwmark: Option<u32>,
    cache: &outline_transport::DnsCache,
) -> Result<()> {
    let addr = match &target {
        TargetAddr::IpV4(ip, port) => SocketAddr::new(std::net::IpAddr::V4(*ip), *port),
        TargetAddr::IpV6(ip, port) => SocketAddr::new(std::net::IpAddr::V6(*ip), *port),
        TargetAddr::Domain(host, port) => outline_transport::resolve_host_with_preference(
            cache,
            host,
            *port,
            &format!("failed to resolve {target}"),
            false,
        )
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow!("no address resolved for {target}"))?,
    };

    let upstream = outline_transport::connect_tcp_socket(addr, fwmark)
        .await
        .with_context(|| format!("direct TCP connect to {target} failed"))?;

    let bound_addr = socket_addr_to_target(client.local_addr()?);
    send_reply(&mut client, SOCKS_STATUS_SUCCESS, &bound_addr).await?;

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    // Activity channel: c2u and u2c signal after every successful read.
    // The idle watcher resets its timer on each token; if the channel is silent
    // for DIRECT_IDLE_TIMEOUT it fires, closing the session.
    //
    // Capacity-1 bounded channel: we only care about "any activity", not how
    // many bytes moved, so a single queued token is enough.  try_send discards
    // the signal when a token is already pending — cheaper than an unbounded
    // channel that accumulates one node per read under high throughput.
    // The watcher exits when both sender halves drop (channel closes → recv → None).
    let (activity_tx, mut activity_rx) = tokio::sync::mpsc::channel::<()>(1);
    let activity_c2u = activity_tx.clone();
    let activity_u2c = activity_tx;

    let c2u = async move {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        loop {
            let read = client_read.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            let _ = activity_c2u.try_send(());
            metrics::add_bytes(
                "tcp",
                "client_to_upstream",
                metrics::DIRECT_GROUP_LABEL,
                metrics::DIRECT_UPLINK_LABEL,
                read,
            );
            upstream_write.write_all(&buf[..read]).await?;
        }
        upstream_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    let u2c = async move {
        let mut buf = vec![0u8; SHADOWSOCKS_MAX_PAYLOAD];
        loop {
            let read = upstream_read.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            let _ = activity_u2c.try_send(());
            metrics::add_bytes(
                "tcp",
                "upstream_to_client",
                metrics::DIRECT_GROUP_LABEL,
                metrics::DIRECT_UPLINK_LABEL,
                read,
            );
            client_write.write_all(&buf[..read]).await?;
        }
        client_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    // Idle watcher: loops receiving activity tokens.  Each received token
    // resets the DIRECT_IDLE_TIMEOUT deadline.  If the deadline expires before
    // the next token (no data in either direction), the future returns,
    // signalling that the session should be forcibly closed.  When the channel
    // is closed (both tasks finished normally), recv() returns None and the
    // watcher exits without triggering the idle path.
    let idle_watcher = async move {
        loop {
            match timeout(DIRECT_IDLE_TIMEOUT, activity_rx.recv()).await {
                Ok(Some(())) => continue,
                Ok(None) => return false, // channel closed — tasks completed normally
                Err(_elapsed) => return true, // idle timeout
            }
        }
    };

    // Drive both halves concurrently.
    //
    // When EITHER side errors, abort the other immediately.
    //
    // When the server closes first (u2c Ok), abort c2u — there is nothing
    // more to forward and waiting for the client to also close is not
    // necessary.
    //
    // When the CLIENT closes first (c2u Ok), give the server a bounded window
    // to flush remaining data and send its own FIN.  Without the timeout a
    // server that keeps the connection half-open indefinitely — e.g. a VPN or
    // signalling server — holds two socket FDs (inbound SOCKS + outbound
    // direct) open forever.
    //
    // If neither side closes and no data flows for DIRECT_IDLE_TIMEOUT, the
    // idle watcher fires and we forcibly close both sides.
    let mut c2u_task = tokio::spawn(c2u);
    let mut u2c_task = tokio::spawn(u2c);
    let mut idle_task = tokio::spawn(idle_watcher);

    tokio::select! {
        c2u_done = &mut c2u_task => {
            idle_task.abort();
            let _ = idle_task.await;
            match c2u_done {
                Ok(Ok(())) => {
                    match timeout(POST_CLIENT_EOF_DOWNSTREAM_TIMEOUT, &mut u2c_task).await {
                        Ok(Ok(result)) => result,
                        Ok(Err(e)) => Err(anyhow!("direct TCP u2c task failed: {e}")),
                        Err(_elapsed) => {
                            info!(
                                %target,
                                timeout_secs = POST_CLIENT_EOF_DOWNSTREAM_TIMEOUT.as_secs(),
                                "direct TCP upstream did not close within timeout after client EOF"
                            );
                            u2c_task.abort();
                            let _ = u2c_task.await;
                            Ok(())
                        }
                    }
                }
                Ok(Err(e)) => { u2c_task.abort(); let _ = u2c_task.await; Err(e) }
                Err(e) => { u2c_task.abort(); let _ = u2c_task.await; Err(anyhow!("direct TCP c2u task panicked: {e}")) }
            }
        }
        u2c_done = &mut u2c_task => {
            idle_task.abort();
            let _ = idle_task.await;
            c2u_task.abort();
            let _ = c2u_task.await;
            match u2c_done {
                Ok(result) => result,
                Err(e) => Err(anyhow!("direct TCP u2c task panicked: {e}")),
            }
        }
        idle_done = &mut idle_task => {
            match idle_done {
                Ok(true) => {
                    // Idle timeout — no data in either direction for DIRECT_IDLE_TIMEOUT.
                    info!(
                        %target,
                        timeout_secs = DIRECT_IDLE_TIMEOUT.as_secs(),
                        "direct TCP session idle timeout — closing"
                    );
                    c2u_task.abort();
                    u2c_task.abort();
                    let _ = c2u_task.await;
                    let _ = u2c_task.await;
                    Ok(())
                }
                Ok(false) => {
                    // The idle channel closed — both data tasks already finished.
                    // abort() is a no-op on a completed task; await to collect
                    // their results and propagate any error instead of swallowing it.
                    c2u_task.abort();
                    u2c_task.abort();
                    let c2u_res = c2u_task.await;
                    let u2c_res = u2c_task.await;
                    match (c2u_res, u2c_res) {
                        (Ok(Err(e)), _) => Err(e),
                        (_, Ok(Err(e))) => Err(e),
                        (Err(e), _) if !e.is_cancelled() => {
                            Err(anyhow!("direct TCP c2u task panicked: {e}"))
                        }
                        (_, Err(e)) if !e.is_cancelled() => {
                            Err(anyhow!("direct TCP u2c task panicked: {e}"))
                        }
                        _ => Ok(()),
                    }
                }
                Err(e) => {
                    c2u_task.abort();
                    u2c_task.abort();
                    let _ = c2u_task.await;
                    let _ = u2c_task.await;
                    Err(anyhow!("direct TCP idle watcher panicked: {e}"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;

    use socks5_proto::SOCKS_STATUS_SUCCESS;

    use super::*;

    /// `handle_tcp_direct` must close the session with `Ok(())` once both
    /// directions have been silent for `DIRECT_IDLE_TIMEOUT`.
    ///
    /// Requires the `test-util` tokio feature (added to dev-dependencies).
    /// Time is paused so the 120-second timeout fires without real waiting.
    #[tokio::test(start_paused = true)]
    async fn handle_tcp_direct_closes_session_after_idle_timeout() {
        // Upstream: accepts but sends nothing (simulates idle server).
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = upstream_listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        // Plumb a loopback pair to act as the SOCKS5 client connection.
        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_listener_addr = client_listener.local_addr().unwrap();
        let (connect_res, accept_res) = tokio::join!(
            tokio::net::TcpStream::connect(client_listener_addr),
            client_listener.accept()
        );
        let mut client_side = connect_res.unwrap();
        let (server_side, _) = accept_res.unwrap();

        let target = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, upstream_port);
        let dns_cache = std::sync::Arc::new(outline_transport::DnsCache::default());
        let direct_task = tokio::spawn(async move {
            handle_tcp_direct(server_side, target, None, &dns_cache).await
        });

        // Drain the 10-byte SOCKS5 SUCCESS reply so the client buffer stays clear.
        let mut socks_reply = [0u8; 10];
        client_side.read_exact(&mut socks_reply).await.unwrap();
        assert_eq!(socks_reply[1], SOCKS_STATUS_SUCCESS, "expected SUCCESS reply");

        // Advance mock time past the idle timeout and yield to let tasks run.
        tokio::time::advance(DIRECT_IDLE_TIMEOUT + Duration::from_secs(1)).await;
        // Multiple yields let the spawned select! arms process the fired timer.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }

        assert!(
            direct_task.is_finished(),
            "handle_tcp_direct should return after idle timeout"
        );
        let result = direct_task.await.unwrap();
        assert!(result.is_ok(), "handle_tcp_direct must return Ok(()) on idle timeout");

        upstream_task.abort();
        let _ = upstream_task.await;
    }
}
