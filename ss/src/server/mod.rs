//! Server entry point.
//!
//! Responsibilities are split across several internal modules:
//! - [`auth`] — HTTP Basic Auth password parsing for the root auth flow.
//! - [`constants`] — tuning constants shared by the bootstrap/transport/shadowsocks paths.
//! - [`state`] — shared application state ([`AppState`], [`TransportRoute`], [`DnsCache`]).
//! - [`setup`] — helpers that turn a parsed [`Config`] into user/route structures.
//! - [`services`] — initialises process-wide services from the config ([`services::Built`]).
//! - [`listeners`] — binds all network sockets ([`listeners::Bound`]).
//! - [`periodic`] — spawns background maintenance tasks.
//! - [`bootstrap`] — listener setup for the websocket, HTTP/3 and metrics endpoints.
//! - [`connect`] — upstream TCP/UDP connect and address resolution.
//! - [`transport`] — websocket/H3 request handlers and the shared session plumbing.
//! - [`shadowsocks`] — the plain (non-websocket) shadowsocks listeners.

use std::{
    collections::BTreeSet,
    sync::Arc,
};

use anyhow::Result;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::config::Config;

mod auth;
mod bootstrap;
mod connect;
mod constants;
mod dns_cache;
mod listeners;
mod nat;
mod periodic;
mod relay;
mod replay;
mod services;
mod setup;
mod shadowsocks;
mod shutdown;
mod state;
mod transport;

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::{
    dns_cache::DnsCache,
    setup::{build_transport_route_map, build_users},
    state::{AuthPolicy, RouteRegistry, Services},
};

use self::{
    bootstrap::{
        build_app, build_metrics_app, ensure_rustls_provider_installed,
        serve_h3_server, serve_metrics_listener, serve_tcp_listener,
    },
    setup::describe_user_routes,
    shadowsocks::{SsTcpCtx, SsUdpCtx, serve_ss_tcp_listener, serve_ss_udp_socket},
    shutdown::{shutdown_channel, wait_for_shutdown_signal},
};

pub async fn run(config: Config) -> Result<()> {
    ensure_rustls_provider_installed();
    let config = Arc::new(config);
    let built = services::build(&config)?;
    let bound = listeners::bind(&config).await?;
    let app = build_app(
        Arc::clone(&built.routes),
        Arc::clone(&built.services),
        Arc::clone(&built.auth),
    );

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

    periodic::spawn_maintenance(&built, &config, shutdown_signal.clone());

    let tcp_paths = built.tcp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let udp_paths = built.udp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let user_routes = describe_user_routes(built.users.as_ref());
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
        users = built.users.len(),
        udp_nat_idle_timeout_secs = config.tuning.udp_nat_idle_timeout_secs,
        prefer_ipv4_upstream = config.prefer_ipv4_upstream,
        outbound_ipv6 = ?built.outbound_ipv6.as_deref().map(|o| o.to_string()),
        "websocket shadowsocks server listening",
    );

    let mut tasks = JoinSet::new();
    if let Some(listener) = bound.listener {
        let config = Arc::clone(&config);
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move { serve_tcp_listener(listener, app, config, shutdown).await });
    }
    if let Some(h3_server) = bound.h3_server {
        let routes = Arc::clone(&built.routes);
        let services = Arc::clone(&built.services);
        let auth = Arc::clone(&built.auth);
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_h3_server(h3_server, routes, services, auth, shutdown).await
        });
    }
    if let Some(metrics_listener) = bound.metrics_listener {
        let metrics_app = build_metrics_app(built.metrics.clone(), config.metrics_path.clone());
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_metrics_listener(metrics_listener, metrics_app, shutdown).await
        });
    }
    if let Some(listener) = bound.ss_tcp_listener {
        let ctx = Arc::new(SsTcpCtx {
            users: built.users.clone(),
            metrics: built.metrics.clone(),
            dns_cache: Arc::clone(&built.dns_cache),
            prefer_ipv4_upstream: config.prefer_ipv4_upstream,
            outbound_ipv6: built.outbound_ipv6.clone(),
        });
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move { serve_ss_tcp_listener(listener, ctx, shutdown).await });
    }
    if let Some(socket) = bound.ss_udp_socket {
        let ctx = Arc::new(SsUdpCtx {
            users: built.users.clone(),
            metrics: built.metrics.clone(),
            nat_table: Arc::clone(&built.nat_table),
            replay_store: Arc::clone(&built.replay_store),
            dns_cache: Arc::clone(&built.dns_cache),
            prefer_ipv4_upstream: config.prefer_ipv4_upstream,
        });
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move { serve_ss_udp_socket(socket, ctx, shutdown).await });
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
