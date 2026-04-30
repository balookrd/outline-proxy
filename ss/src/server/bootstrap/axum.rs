use std::{net::SocketAddr, sync::Arc};

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
        H2_KEEPALIVE_INTERVAL_SECS, H2_KEEPALIVE_TIMEOUT_SECS,
        HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS, TLS_MAX_CONCURRENT_CONNECTIONS,
    },
    shutdown::ShutdownSignal,
    state::{AppState, AuthPolicy, RoutesSnapshot, Services},
    transport::{
        HttpFallbackContext, XhttpAxumState, http_fallback_handler, metrics_handler,
        not_found_handler, root_http_auth_handler, sni_fallback, tcp_websocket_upgrade,
        udp_websocket_upgrade, vless_websocket_upgrade, xhttp_handler,
    },
};
use sni_fallback::SniFallbackContext;
use super::tls::build_tcp_tls_acceptor;

pub(in crate::server) fn build_app(
    routes: RoutesSnapshot,
    services: Arc<Services>,
    auth: Arc<AuthPolicy>,
    http_fallback: Option<Arc<HttpFallbackContext>>,
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
    let xhttp_paths: Vec<String> = snap.xhttp_vless.keys().cloned().collect();
    drop(snap);

    let state = AppState {
        routes: Arc::clone(&routes),
        services: Arc::clone(&services),
        auth,
        http_fallback,
    };
    let fallback_route = if state.http_fallback.is_some() {
        any(http_fallback_handler)
    } else {
        any(not_found_handler)
    };
    let mut app = router.fallback(fallback_route).with_state(state.clone());

    // XHTTP routes carry their own `XhttpAxumState`, so they have to
    // be merged in after the main router pins its state. The base
    // path is captured once per route and the `{id}` segment is
    // appended for axum to extract.
    for base in xhttp_paths {
        let xhttp_state = XhttpAxumState {
            base_path: Arc::from(base.as_str()),
            registry: Arc::clone(&services.xhttp_registry),
            parent: state.clone(),
        };
        let route_pattern = format!("{base}/{{id}}");
        let xhttp_router = Router::new()
            .route(&route_pattern, any(xhttp_handler))
            .with_state(xhttp_state);
        app = app.merge(xhttp_router);
    }
    app
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
    sni_fallback: Option<Arc<SniFallbackContext>>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    if config.tcp_tls_enabled() {
        let acceptor = build_tcp_tls_acceptor(config.as_ref())?;
        serve_tls_listener(listener, app, acceptor, config.tuning, sni_fallback, shutdown).await
    } else {
        // SNI fallback only makes sense for the TLS path. Validation
        // already rejects `[sni_fallback]` without TLS so the
        // `Some(_)` branch is unreachable here in practice; assert
        // it explicitly to catch future drift.
        debug_assert!(sni_fallback.is_none(), "sni_fallback requires TLS");
        serve_listener(listener, app, shutdown).await
    }
}

pub(in crate::server) async fn serve_listener(
    listener: TcpListener,
    app: Router,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let listener = listener.tap_io(|stream| {
        if let Err(error) = configure_tcp_stream(stream) {
            warn!(?error, "failed to configure accepted http connection");
        }
    });
    let mut shutdown_for_graceful = shutdown.clone();
    // `into_make_service_with_connect_info::<SocketAddr>()` injects a
    // `ConnectInfo<SocketAddr>` extension into every request so the
    // TCP-WS upgrade handler can key the per-route peer-user hint cache.
    let serve = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move { shutdown_for_graceful.cancelled().await });
    drain_axum_serve(async move { serve.await }, shutdown, "plain tcp").await
}

pub(in crate::server) async fn serve_metrics_listener(
    listener: TcpListener,
    app: Router,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let mut shutdown_for_graceful = shutdown.clone();
    let serve = axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown_for_graceful.cancelled().await });
    drain_axum_serve(async move { serve.await }, shutdown, "metrics").await
}

// hyper's graceful_shutdown holds the per-connection task open for the full
// lifetime of any upgraded WebSocket stream, so without a cap the listener
// future never resolves on SIGTERM. After `shutdown` fires we wait at most
// `HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS` for in-flight connections to finish,
// then drop the serve future to abort remaining hyper connection tasks.
async fn drain_axum_serve<F>(
    serve: F,
    mut shutdown: ShutdownSignal,
    label: &'static str,
) -> Result<()>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    let drain_timeout = Duration::from_secs(HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
    let drain_deadline = async move {
        shutdown.cancelled().await;
        tokio::time::sleep(drain_timeout).await;
    };
    tokio::select! {
        biased;
        result = serve => result.with_context(|| format!("{label} server exited unexpectedly")),
        _ = drain_deadline => {
            warn!(
                listener = label,
                timeout_secs = HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
                "connections did not drain within shutdown timeout; aborting"
            );
            Ok(())
        }
    }
}

async fn serve_tls_listener(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
    profile: TuningProfile,
    sni_fallback: Option<Arc<SniFallbackContext>>,
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
        let sni_fallback = sni_fallback.clone();
        let mut task_shutdown = shutdown.clone();

        tasks.spawn(async move {
            let _permit = permit;

            // SNI dispatch: when [sni_fallback] is configured, peek
            // the ClientHello before handshake. Foreign SNIs (or no
            // SNI when `allow_no_sni = false`) are spliced as raw
            // TCP to the configured backend; matching SNIs continue
            // through the local TLS terminator with the buffered
            // bytes prepended. Wrapping in `PrependStream` even when
            // the buffer is empty keeps the type uniform across the
            // two branches without paying for `Box<dyn ...>`.
            let stream_for_handshake = if let Some(ctx) = sni_fallback.as_ref() {
                let dispatch = tokio::select! {
                    biased;
                    _ = task_shutdown.cancelled() => {
                        debug!(%peer_addr, "aborting SNI peek on shutdown");
                        return;
                    }
                    res = sni_fallback::dispatch_sni(ctx, stream, peer_addr) => res,
                };
                match dispatch {
                    Ok(Some(prepended)) => prepended,
                    Ok(None) => return,
                    Err(_) => return,
                }
            } else {
                sni_fallback::PrependStream::new(Vec::new(), stream)
            };

            let tls_stream = tokio::select! {
                biased;
                _ = task_shutdown.cancelled() => {
                    debug!(%peer_addr, "aborting TLS handshake on shutdown");
                    return;
                }
                res = acceptor.accept(stream_for_handshake) => match res {
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
            // Inject `ConnectInfo<SocketAddr>` so the TCP-WS upgrade
            // handler can key the per-route peer-user hint cache the
            // same way the plain (non-TLS) path does.
            let app_with_addr =
                app.layer(axum::Extension(axum::extract::ConnectInfo(peer_addr)));
            let service = TowerToHyperService::new(app_with_addr);
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

    let drain_timeout = Duration::from_secs(HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
    let drain =
        tokio::time::timeout(drain_timeout, async { while tasks.join_next().await.is_some() {} })
            .await;
    if drain.is_err() {
        warn!(
            remaining = tasks.len(),
            timeout_secs = HTTP_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
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
#[path = "tests/axum.rs"]
mod tests;
