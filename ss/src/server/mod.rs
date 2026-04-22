//! Server entry point.
//!
//! Responsibilities are split across several internal modules:
//! - [`auth`] — HTTP Basic Auth password parsing for the root auth flow.
//! - [`constants`] — tuning constants shared by the bootstrap/transport/shadowsocks paths.
//! - [`state`] — shared application state ([`AppState`], [`TransportRoute`], [`DnsCache`]).
//! - [`setup`] — helpers that turn a parsed [`Config`] into user/route structures.
//! - [`bootstrap`] — listener setup for the websocket, HTTP/3 and metrics endpoints.
//! - [`connect`] — upstream TCP/UDP connect and address resolution.
//! - [`transport`] — websocket/H3 request handlers and the shared session plumbing.
//! - [`shadowsocks`] — the plain (non-websocket) shadowsocks listeners.

use std::{
    collections::BTreeSet,
    sync::Arc,
};

use anyhow::{Context, Result};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::Duration,
};
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    metrics::{Metrics, Transport},
    nat::NatTable,
    outbound::{InterfaceSource, OutboundIpv6},
};

mod auth;
mod bootstrap;
mod connect;
mod constants;
mod dns_cache;
mod relay;
mod setup;
mod shadowsocks;
mod shutdown;
mod state;
mod transport;

#[cfg(test)]
mod tests;

use self::{
    bootstrap::{
        build_app, build_h3_server, build_metrics_app, ensure_rustls_provider_installed,
        serve_h3_server, serve_metrics_listener, serve_tcp_listener,
    },
    constants::{DNS_CACHE_STALE_GRACE_SECS, DNS_CACHE_SWEEP_INTERVAL_SECS, UDP_DNS_CACHE_TTL_SECS},
    dns_cache::DnsCache,
    setup::{build_transport_route_map, build_users, describe_user_routes},
    shadowsocks::{serve_ss_tcp_listener, serve_ss_udp_socket},
    shutdown::{shutdown_channel, wait_for_shutdown_signal},
    state::{AuthPolicy, RouteRegistry, Services},
};

pub async fn run(config: Config) -> Result<()> {
    ensure_rustls_provider_installed();
    let config = Arc::new(config);
    let metrics = Metrics::new(config.as_ref());
    metrics.start_process_memory_sampler();
    let users = build_users(&config)?;
    let tcp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
    let outbound_ipv6: Option<Arc<OutboundIpv6>> = if let Some(prefix) = config.outbound_ipv6_prefix {
        Some(Arc::new(OutboundIpv6::Prefix(prefix)))
    } else if let Some(iface) = config.outbound_ipv6_interface.clone() {
        let source = InterfaceSource::bind(iface).with_context(|| {
            format!(
                "failed to enumerate IPv6 addresses on outbound interface {:?}",
                config.outbound_ipv6_interface,
            )
        })?;
        Some(Arc::new(OutboundIpv6::Interface(source)))
    } else {
        None
    };
    let nat_table = NatTable::with_outbound_ipv6(
        Duration::from_secs(config.tuning.udp_nat_idle_timeout_secs),
        outbound_ipv6.clone(),
    );
    let dns_cache = DnsCache::new(Duration::from_secs(UDP_DNS_CACHE_TTL_SECS));
    let routes = Arc::new(RouteRegistry {
        tcp: Arc::clone(&tcp_routes),
        udp: Arc::clone(&udp_routes),
    });
    let udp_relay_semaphore = if config.tuning.udp_max_concurrent_relay_tasks == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(
            config.tuning.udp_max_concurrent_relay_tasks,
        )))
    };
    let services = Arc::new(Services {
        metrics: metrics.clone(),
        nat_table: Arc::clone(&nat_table),
        dns_cache: Arc::clone(&dns_cache),
        prefer_ipv4_upstream: config.prefer_ipv4_upstream,
        outbound_ipv6: outbound_ipv6.clone(),
        udp_relay_semaphore,
    });
    let auth = Arc::new(AuthPolicy {
        users: users.clone(),
        http_root_auth: config.http_root_auth,
        http_root_realm: Arc::from(config.http_root_realm.clone()),
    });
    let app = build_app(Arc::clone(&routes), Arc::clone(&services), Arc::clone(&auth));
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

    // Periodic re-enumeration of the outbound IPv6 interface address pool.
    // Only spawned when interface-mode source selection is configured.
    if let Some(OutboundIpv6::Interface(source)) = outbound_ipv6.as_deref() {
        let source = Arc::clone(source);
        let period = Duration::from_secs(config.outbound_ipv6_refresh_secs);
        let mut shutdown = shutdown_signal.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await; // skip the immediate tick; initial pool came from bind()
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => break,
                    _ = interval.tick() => source.refresh(),
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
        udp_nat_idle_timeout_secs = config.tuning.udp_nat_idle_timeout_secs,
        prefer_ipv4_upstream = config.prefer_ipv4_upstream,
        outbound_ipv6 = ?outbound_ipv6.as_deref().map(|o| o.to_string()),
        "websocket shadowsocks server listening",
    );

    let mut tasks = JoinSet::new();
    if let Some(listener) = listener {
        let config = Arc::clone(&config);
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move { serve_tcp_listener(listener, app, config, shutdown).await });
    }
    if let Some(h3_server) = h3_server {
        let routes = Arc::clone(&routes);
        let services = Arc::clone(&services);
        let auth = Arc::clone(&auth);
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_h3_server(h3_server, routes, services, auth, shutdown).await
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
        let outbound_ipv6 = outbound_ipv6.clone();
        let shutdown = shutdown_signal.clone();
        tasks.spawn(async move {
            serve_ss_tcp_listener(
                listener,
                users,
                metrics,
                dns_cache,
                prefer_ipv4_upstream,
                outbound_ipv6,
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
