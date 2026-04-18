//! Server entry point.
//!
//! Responsibilities are split across several internal modules:
//! - [`constants`] — tuning constants shared by the bootstrap/transport/shadowsocks paths.
//! - [`state`] — shared application state ([`AppState`], [`TransportRoute`], [`DnsCache`]).
//! - [`setup`] — helpers that turn a parsed [`Config`] into user/route structures.
//! - [`bootstrap`] — listener setup for the websocket, HTTP/3 and metrics endpoints.
//! - [`connect`] — upstream TCP/UDP connect and address resolution.
//! - [`transport`] — websocket/H3 request handlers and the shared session plumbing.
//! - [`shadowsocks`] — the plain (non-websocket) shadowsocks listeners.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use bytes::{Bytes, BytesMut};

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{
        OriginalUri, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Method, StatusCode, Version},
    response::IntoResponse,
    routing::any,
    serve::ListenerExt,
};
use futures_util::{FutureExt, SinkExt, StreamExt, stream::FuturesUnordered};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sockudo_ws::{
    Config as H3WebSocketConfig, ExtendedConnectRequest as H3ExtendedConnectRequest,
    Http3 as H3Transport, Message as H3Message, Stream as H3Stream,
    WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::{Duration, timeout},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE, UserKey,
        decrypt_udp_packet, decrypt_udp_packet_with_hint, diagnose_stream_handshake,
        diagnose_udp_packet,
    },
    fwmark::apply_fwmark_if_needed,
    metrics::{DisconnectReason, Metrics, Protocol, TcpUpstreamGuard, Transport},
    nat::{NatKey, NatTable, UdpResponseSender},
    protocol::{TargetAddr, parse_target_addr},
};

mod bootstrap;
mod connect;
mod constants;
mod dns_cache;
mod setup;
mod shadowsocks;
mod shutdown;
mod state;
mod transport;

#[cfg(test)]
mod tests;

// Re-export submodule contents at the `server` level so existing `use super::*;`
// imports in the sibling modules (bootstrap/connect/shadowsocks/transport) keep
// resolving against a single flat namespace.
use self::{
    bootstrap::{
        build_app, build_h3_server, build_metrics_app, ensure_rustls_provider_installed,
        serve_h3_server, serve_metrics_listener, serve_tcp_listener,
    },
    connect::connect_tcp_target,
    constants::*,
    dns_cache::DnsCache,
    setup::{
        build_transport_route_map, build_users, describe_user_routes, protocol_from_http_version,
    },
    shadowsocks::{serve_ss_tcp_listener, serve_ss_udp_socket},
    shutdown::{shutdown_channel, wait_for_shutdown_signal},
    state::{AppState, TransportRoute, empty_transport_route},
    transport::{is_benign_ws_disconnect, tcp_websocket_upgrade, udp_websocket_upgrade},
};

pub async fn run(config: Config) -> Result<()> {
    ensure_rustls_provider_installed();
    let config = Arc::new(config);
    let metrics = Metrics::new(config.as_ref());
    metrics.start_process_memory_sampler();
    let users = build_users(&config)?;
    let tcp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
    let nat_table = NatTable::new(Duration::from_secs(config.udp_nat_idle_timeout_secs));
    let dns_cache = DnsCache::new(Duration::from_secs(UDP_DNS_CACHE_TTL_SECS));
    let app = build_app(
        users.clone(),
        tcp_routes.clone(),
        udp_routes.clone(),
        metrics.clone(),
        Arc::clone(&nat_table),
        Arc::clone(&dns_cache),
        config.prefer_ipv4_upstream,
        config.http_root_auth,
        config.http_root_realm.clone(),
    );
    let listener = if let Some(listen) = config.listen {
        Some(
            TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to bind {}", listen))?,
        )
    } else {
        None
    };
    let ss_tcp_listener =
        if let Some(ss_listen) = config.ss_listen {
            Some(TcpListener::bind(ss_listen).await.with_context(|| {
                format!("failed to bind shadowsocks tcp listener {}", ss_listen)
            })?)
        } else {
            None
        };
    let ss_udp_socket = if let Some(ss_listen) = config.ss_listen {
        Some(Arc::new(UdpSocket::bind(ss_listen).await.with_context(|| {
            format!("failed to bind shadowsocks udp socket {}", ss_listen)
        })?))
    } else {
        None
    };
    let metrics_listener = if config.metrics_enabled() {
        let metrics_listen = config.metrics_listen.expect("metrics listen must exist");
        Some(
            TcpListener::bind(metrics_listen)
                .await
                .with_context(|| format!("failed to bind metrics listener {}", metrics_listen))?,
        )
    } else {
        None
    };
    let h3_server = if config.h3_enabled() {
        Some(build_h3_server(config.as_ref()).await?)
    } else {
        None
    };

    let (shutdown_sender, shutdown_signal) = shutdown_channel();

    // OS signal handler: flip the shutdown flag on SIGTERM/SIGINT.
    {
        let shutdown_sender = Arc::new(shutdown_sender);
        let handler_sender = Arc::clone(&shutdown_sender);
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            handler_sender.send();
        });
        // Drop the strong reference we hold locally so the handler task owns
        // the only remaining `ShutdownSender`.  Dropping it after the handler
        // fires eagerly releases resources, but the handler is the only place
        // that actually needs to `send()`.
        drop(shutdown_sender);
    }

    // Periodic NAT entry eviction.
    {
        let nat_table_cleanup = Arc::clone(&nat_table);
        let metrics_cleanup = Arc::clone(&metrics);
        let mut shutdown = shutdown_signal.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        nat_table_cleanup.evict_idle(&metrics_cleanup).await;
                    }
                }
            }
        });
    }

    // Periodic sweep of DNS cache entries whose stale-fallback grace expired.
    {
        let dns_cache_cleanup = Arc::clone(&dns_cache);
        let mut shutdown = shutdown_signal.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(DNS_CACHE_SWEEP_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let purged = dns_cache_cleanup
                            .sweep_expired(Duration::from_secs(DNS_CACHE_STALE_GRACE_SECS));
                        if purged > 0 {
                            debug!(purged, "swept expired dns cache entries");
                        }
                    }
                }
            }
        });
    }

    let tcp_paths = tcp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let udp_paths = udp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let user_routes = describe_user_routes(users.as_ref());
    info!(
        listen = ?config.listen,
        ss_listen = ?config.ss_listen,
        tcp_tls = config.tcp_tls_enabled(),
        h3_listen = ?config.effective_h3_listen(),
        metrics_listen = ?config.metrics_listen,
        metrics_path = %config.metrics_path,
        default_tcp_ws_path = %config.ws_path_tcp,
        default_udp_ws_path = %config.ws_path_udp,
        tcp_ws_paths = ?tcp_paths,
        udp_ws_paths = ?udp_paths,
        user_routes = ?user_routes,
        method = ?config.method,
        users = users.len(),
        udp_nat_idle_timeout_secs = config.udp_nat_idle_timeout_secs,
        prefer_ipv4_upstream = config.prefer_ipv4_upstream,
        "websocket shadowsocks server listening",
    );

    let mut tasks = JoinSet::new();
    if let Some(listener) = listener {
        let config = Arc::clone(&config);
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move { serve_tcp_listener(listener, app, config, shutdown).await });
    }
    if let Some(h3_server) = h3_server {
        let users = users.clone();
        let tcp_routes = tcp_routes.clone();
        let udp_routes = udp_routes.clone();
        let metrics = metrics.clone();
        let nat_table = Arc::clone(&nat_table);
        let dns_cache = Arc::clone(&dns_cache);
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        let http_root_auth = config.http_root_auth;
        let http_root_realm = config.http_root_realm.clone();
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_h3_server(
                h3_server,
                users,
                tcp_routes,
                udp_routes,
                metrics,
                nat_table,
                dns_cache,
                prefer_ipv4_upstream,
                http_root_auth,
                http_root_realm,
                shutdown,
            )
            .await
        });
    }
    if let Some(metrics_listener) = metrics_listener {
        let metrics_app = build_metrics_app(metrics.clone(), config.metrics_path.clone());
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_metrics_listener(metrics_listener, metrics_app, shutdown).await
        });
    }
    if let Some(listener) = ss_tcp_listener {
        let users = users.clone();
        let metrics = metrics.clone();
        let dns_cache = Arc::clone(&dns_cache);
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_ss_tcp_listener(
                listener,
                users,
                metrics,
                dns_cache,
                prefer_ipv4_upstream,
                shutdown,
            )
            .await
        });
    }
    if let Some(socket) = ss_udp_socket {
        let users = users.clone();
        let metrics = metrics.clone();
        let nat_table = Arc::clone(&nat_table);
        let dns_cache = Arc::clone(&dns_cache);
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_ss_udp_socket(
                socket,
                users,
                metrics,
                nat_table,
                dns_cache,
                prefer_ipv4_upstream,
                shutdown,
            )
            .await
        });
    }

    // `shutdown_signal` lives past the spawn block so receivers inherited above
    // can observe cancellation; drop our copy so the watch channel can close
    // cleanly once the OS-signal task fires.
    drop(shutdown_signal);

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {},
            Ok(Err(error)) => warn!(?error, "server task exited with error"),
            Err(join_error) => warn!(?join_error, "server task panicked"),
        }
    }
    info!("all server tasks stopped; shutdown complete");
    Ok(())
}
