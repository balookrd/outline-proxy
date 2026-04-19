use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::config::AppConfig;
use crate::proxy::{self, ProxyConfig};
use outline_uplink::UplinkRegistry;

pub(super) fn warn_about_tcp_probe_target(config: &AppConfig) {
    for group in &config.groups {
        let Some(tcp_probe) = group.probe.tcp.as_ref() else {
            continue;
        };
        if matches!(tcp_probe.port, 80 | 443 | 8080 | 8443) {
            warn!(
                group = %group.name,
                host = %tcp_probe.host,
                port = tcp_probe.port,
                "probe.tcp waits for the remote side to send bytes or close cleanly; \
                 HTTP/HTTPS-style targets on common web ports usually wait for a client request \
                 and will time out. Prefer probe.http for HTTP endpoints or use a speak-first \
                 TCP service for probe.tcp"
            );
        }
    }
}

pub(super) async fn run_accept_loop(
    listener: TcpListener,
    proxy_config: Arc<ProxyConfig>,
    registry: UplinkRegistry,
) -> Result<()> {
    // Cap concurrent in-flight connections to bound task memory under DDoS.
    // Accepting continues at full speed; only the spawn blocks when the limit
    // is reached, which naturally applies backpressure to the accept loop.
    const MAX_CONCURRENT_CONNECTIONS: usize = 4096;
    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    // Exponential backoff state for EMFILE / ENFILE.  Reset on every
    // successful accept so that a temporary FD spike doesn't permanently
    // slow down new connections.
    let mut fd_backoff = Duration::ZERO;
    /// First sleep after hitting the FD limit.
    const FD_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
    /// Hard ceiling — prevents a sustained FD exhaustion from sleeping
    /// longer than a few seconds between retries.
    const FD_BACKOFF_MAX: Duration = Duration::from_secs(5);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => {
                // Successful accept: any previous FD backoff is no longer
                // relevant — connections are flowing again.
                fd_backoff = Duration::ZERO;
                v
            },
            Err(e) => {
                // ECONNABORTED: the client withdrew the connection before
                // accept() returned.  This is harmless; just try again.
                if e.kind() == std::io::ErrorKind::ConnectionAborted {
                    continue;
                }
                // EMFILE / ENFILE: process or system FD limit reached.
                // Back off with exponential delay (50 ms → 100 → 200 → …
                // capped at 5 s) so that pending cleanup tasks (H2 driver
                // tasks, writer tasks) have a chance to run and free FDs.
                // A fixed 10 ms sleep would spin uselessly under sustained
                // exhaustion; the growing delay avoids a self-inflicted
                // busy-loop while still recovering quickly when FDs free up.
                let raw = e.raw_os_error();
                if raw == Some(libc::EMFILE) || raw == Some(libc::ENFILE) {
                    fd_backoff = if fd_backoff.is_zero() {
                        FD_BACKOFF_INITIAL
                    } else {
                        (fd_backoff * 2).min(FD_BACKOFF_MAX)
                    };
                    warn!(
                        error = %e,
                        backoff_ms = fd_backoff.as_millis(),
                        "accept failed (FD limit hit), backing off"
                    );
                    tokio::time::sleep(fd_backoff).await;
                    continue;
                }
                return Err(e).context("accept failed");
            },
        };
        // Arm aggressive TCP keepalive on the inbound SOCKS5 socket so the
        // TUN/SOCKS5 layer in front of us (sing-box, clash, mihomo) does not
        // silently close long-lived idle flows like SSH.  Failures are
        // non-fatal: log and keep the connection, since the effect is only
        // degradation to the pre-fix behaviour.
        if let Err(error) = outline_transport::configure_inbound_tcp_stream(&stream, peer) {
            debug!(%peer, error = %format!("{error:#}"), "failed to arm inbound TCP keepalive; proceeding without it");
        }
        let config = Arc::clone(&proxy_config);
        let registry = registry.clone();
        let permit = conn_sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = proxy::handle_client(stream, peer, config, registry).await {
                if crate::error_text::is_expected_client_disconnect(&error) {
                    debug!(%peer, error = %format!("{error:#}"), "connection closed by client");
                } else if crate::error_text::is_client_write_disconnect(&error) {
                    warn!(
                        %peer,
                        error = %format!("{error:#}"),
                        "client disconnected before proxy finished sending the response"
                    );
                } else {
                    warn!(%peer, error = %format!("{error:#}"), "connection failed");
                }
            }
        });
    }
}
