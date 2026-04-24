use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Router, routing::any, serve::ListenerExt};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::Duration};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::{
    config::{Config, TuningProfile},
    metrics::Metrics,
};

use super::super::{
    connect::configure_tcp_stream,
    constants::{
        H2_KEEPALIVE_INTERVAL_SECS, H2_KEEPALIVE_TIMEOUT_SECS, TLS_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
        TLS_MAX_CONCURRENT_CONNECTIONS,
    },
    shutdown::ShutdownSignal,
    state::{AppState, AuthPolicy, RoutesSnapshot, Services},
    transport::{
        metrics_handler, not_found_handler, root_http_auth_handler, tcp_websocket_upgrade,
        udp_websocket_upgrade, vless_websocket_upgrade,
    },
};
use super::tls::build_tcp_tls_acceptor;

pub(in crate::server) fn build_app(
    routes: RoutesSnapshot,
    services: Arc<Services>,
    auth: Arc<AuthPolicy>,
) -> Router {
    let mut router = Router::new();

    if auth.http_root_auth {
        router = router.route("/", any(root_http_auth_handler));
    }

    let snap = routes.load();
    for path in snap.tcp.keys() {
        router = router.route(path, any(tcp_websocket_upgrade));
    }

    for path in snap.udp.keys() {
        router = router.route(path, any(udp_websocket_upgrade));
    }

    for path in snap.vless.keys() {
        router = router.route(path, any(vless_websocket_upgrade));
    }
    drop(snap);

    let state = AppState { routes, services, auth };
    router.fallback(any(not_found_handler)).with_state(state)
}

pub(in crate::server) fn build_metrics_app(metrics: Arc<Metrics>, metrics_path: String) -> Router {
    Router::new()
        .route(&metrics_path, any(metrics_handler))
        .with_state(metrics)
}

pub(in crate::server) async fn serve_tcp_listener(
    listener: TcpListener,
    app: Router,
    config: Arc<Config>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    if config.tcp_tls_enabled() {
        let acceptor = build_tcp_tls_acceptor(config.as_ref())?;
        serve_tls_listener(listener, app, acceptor, config.tuning, shutdown).await
    } else {
        serve_listener(listener, app, shutdown).await
    }
}

pub(in crate::server) async fn serve_listener(
    listener: TcpListener,
    app: Router,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let listener = listener.tap_io(|stream| {
        if let Err(error) = configure_tcp_stream(stream) {
            warn!(?error, "failed to configure accepted http connection");
        }
    });
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("server exited unexpectedly")
}

pub(in crate::server) async fn serve_metrics_listener(
    listener: TcpListener,
    app: Router,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await
        .context("metrics server exited unexpectedly")
}

async fn serve_tls_listener(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
    profile: TuningProfile,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    let connection_limit = Arc::new(Semaphore::new(TLS_MAX_CONCURRENT_CONNECTIONS));
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        // Reap already-finished tasks so JoinSet storage stays bounded under
        // long-lived listeners with high connection churn.
        while tasks.try_join_next().is_some() {}

        let permit = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("TLS listener stopping on shutdown signal");
                break;
            }
            permit = connection_limit.clone().acquire_owned() => {
                // The semaphore is never closed while the listener is running.
                permit.expect("TLS connection semaphore unexpectedly closed")
            }
        };

        let (stream, peer_addr) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                debug!("TLS listener stopping on shutdown signal");
                break;
            }
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(error) => {
                    warn!(?error, "failed to accept TLS tcp connection");
                    continue;
                },
            },
        };
        if let Err(error) = configure_tcp_stream(&stream) {
            warn!(%peer_addr, ?error, "failed to configure TLS tcp connection");
            continue;
        }
        let acceptor = acceptor.clone();
        let app = app.clone();
        let mut task_shutdown = shutdown.clone();

        tasks.spawn(async move {
            let _permit = permit;
            let tls_stream = tokio::select! {
                biased;
                _ = task_shutdown.cancelled() => {
                    debug!(%peer_addr, "aborting TLS handshake on shutdown");
                    return;
                }
                res = acceptor.accept(stream) => match res {
                    Ok(s) => s,
                    Err(error) => {
                        if is_benign_tls_handshake_error(&error) {
                            debug!(?error, %peer_addr, "tls handshake closed before completion");
                        } else {
                            warn!(?error, %peer_addr, "tls handshake failed");
                        }
                        return;
                    },
                },
            };

            let io = TokioIo::new(tls_stream);
            let service = TowerToHyperService::new(app);
            let builder = build_http_server_builder(&profile);
            let conn = builder.serve_connection_with_upgrades(io, service);
            tokio::pin!(conn);

            let result = tokio::select! {
                biased;
                res = conn.as_mut() => res,
                _ = task_shutdown.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    conn.as_mut().await
                }
            };
            if let Err(error) = result
                && !is_benign_http_serve_error(error.as_ref())
            {
                warn!(?error, %peer_addr, "tls http server connection terminated with error");
            }
        });
    }

    let drain_timeout = Duration::from_secs(TLS_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
    let drain =
        tokio::time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await;
    if drain.is_err() {
        warn!(
            remaining = tasks.len(),
            timeout_secs = TLS_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
            "TLS connections did not drain within shutdown timeout; aborting"
        );
        tasks.shutdown().await;
    } else {
        debug!("TLS listener drained all connections");
    }
    Ok(())
}

fn build_http_server_builder(profile: &TuningProfile) -> HyperBuilder<TokioExecutor> {
    let mut builder = HyperBuilder::new(TokioExecutor::new());
    builder
        .http2()
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .initial_stream_window_size(Some(profile.h2_stream_window_bytes))
        .initial_connection_window_size(Some(profile.h2_connection_window_bytes))
        .max_send_buf_size(profile.h2_max_send_buf_size)
        .keep_alive_interval(Some(Duration::from_secs(H2_KEEPALIVE_INTERVAL_SECS)))
        .keep_alive_timeout(Duration::from_secs(H2_KEEPALIVE_TIMEOUT_SECS));
    builder
}

fn is_benign_http_serve_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(cause) = source {
        if let Some(hy) = cause.downcast_ref::<hyper::Error>()
            && (hy.is_canceled() || hy.is_incomplete_message() || hy.is_closed())
        {
            return true;
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            if matches!(
                io.kind(),
                ConnectionReset | BrokenPipe | UnexpectedEof | ConnectionAborted,
            ) {
                return true;
            }
        }
        source = cause.source();
    }
    false
}

fn is_benign_tls_handshake_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionAborted,
    )
}

#[cfg(test)]
mod tests {
    use super::is_benign_tls_handshake_error;

    #[test]
    fn tls_handshake_unexpected_eof_is_benign() {
        let error = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tls handshake eof");
        assert!(is_benign_tls_handshake_error(&error));
    }

    #[test]
    fn tls_handshake_protocol_failure_is_not_benign() {
        let error = std::io::Error::other("received corrupt message");
        assert!(!is_benign_tls_handshake_error(&error));
    }
}
