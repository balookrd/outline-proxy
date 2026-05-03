//! Shared accept-loop with graceful shutdown for the embedded HTTP listeners
//! (metrics, control, dashboard).
//!
//! Each listener races `accept()` against the global shutdown watch, caps
//! in-flight connections via a semaphore, cancels per-connection futures on
//! SIGTERM, and drains remaining work with a short timeout before returning.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tracing::{debug, info, warn};

pub(crate) struct ServeConfig {
    pub server_name: &'static str,
    pub max_concurrent: usize,
    pub drain_timeout: Duration,
}

/// Run an HTTP accept loop until `shutdown` flips to `true`, then drain
/// in-flight requests for at most `drain_timeout` before returning.
///
/// `handle` is called once per accepted connection. Failures are logged with
/// the connection peer address; the accept loop never aborts on a per-request
/// error (only fatal `accept()` failures propagate up).
pub(crate) async fn serve_with_shutdown<F, Fut>(
    listener: TcpListener,
    config: ServeConfig,
    mut shutdown: watch::Receiver<bool>,
    handle: F,
) -> Result<()>
where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let conn_sem = Arc::new(Semaphore::new(config.max_concurrent));
    let server = config.server_name;

    loop {
        let accept_res = tokio::select! {
            res = listener.accept() => Some(res),
            _ = shutdown.changed() => None,
        };
        let Some(accept_res) = accept_res else { break };

        let (stream, peer) = match accept_res {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("{server} accept failed"));
            },
        };

        let permit = conn_sem
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore closed");
        let handle = handle.clone();
        let mut task_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                res = handle(stream, peer) => {
                    if let Err(error) = res {
                        warn!(server, %peer, error = %format!("{error:#}"), "request failed");
                    }
                }
                _ = task_shutdown.wait_for(|&v| v) => {
                    debug!(server, %peer, "connection cancelled by shutdown");
                }
            }
        });
    }

    let in_flight = config
        .max_concurrent
        .saturating_sub(conn_sem.available_permits());
    info!(server, in_flight, "draining HTTP connections before exit");
    if in_flight > 0 {
        tokio::select! {
            _ = conn_sem.acquire_many(config.max_concurrent as u32) => {
                info!(server, "HTTP connections drained cleanly");
            },
            _ = tokio::time::sleep(config.drain_timeout) => {
                warn!(
                    server,
                    timeout_secs = config.drain_timeout.as_secs(),
                    "drain timeout reached, forcing exit"
                );
            },
        }
    }

    Ok(())
}
