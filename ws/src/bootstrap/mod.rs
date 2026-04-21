use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::AppConfig;
use crate::proxy::ProxyConfig;
#[cfg(feature = "control")]
use crate::http::control::spawn_control_server;
#[cfg(feature = "metrics")]
use crate::http::metrics::spawn_metrics_server;
use outline_uplink::{UplinkRegistry, log_registry_summary};

mod listener;
mod state_store;

pub async fn run_with_config(config: AppConfig) -> Result<()> {
    let state_store = state_store::init(config.state_path.clone()).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate())
                .expect("SIGTERM handler registration failed");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        warn!("shutdown signal received, draining active connections");
        let _ = shutdown_tx.send(true);
    });

    // Shared DNS cache used by every transport resolve path. Built here
    // (not stored in AppConfig) so the runtime paths receive the same
    // Arc<DnsCache> without a two-phase init on the declarative config.
    let dns_cache = Arc::new(outline_transport::DnsCache::new(
        outline_transport::DEFAULT_DNS_CACHE_TTL,
    ));

    let registry =
        UplinkRegistry::new_with_state(config.groups.clone(), state_store, dns_cache.clone())
            .await?;
    registry.initialize_strict_active_selection().await;
    registry.spawn_probe_loops();
    registry.spawn_warm_standby_loops();
    registry.spawn_standby_keepalive_loops();
    registry.spawn_shared_connection_gc_loop();

    // Compile the policy routing table (if user declared [[route]]) and
    // spawn per-rule file watchers for hot-reload.
    let routing_table = if let Some(routing_cfg) = config.routing.clone() {
        let table = Arc::new(
            outline_routing::RoutingTable::compile(&routing_cfg)
                .await
                .context("failed to compile routing table")?,
        );
        outline_routing::spawn_route_watchers(Arc::clone(&table));
        Some(table)
    } else {
        None
    };

    // TUN dispatches through the policy routing table, falling back to the
    // default group when no [[route]] is configured.
    #[cfg(feature = "tun")]
    {
        let tun_routing = outline_tun::TunRouting::new(
            registry.clone(),
            routing_table.clone(),
            config.direct_fwmark,
        );
        if let Some(tun) = config.tun.clone() {
            outline_tun::spawn_tun_loop(tun, tun_routing, dns_cache.clone())
                .await
                .context("failed to start TUN loop")?;
        }
    }

    let listener = if let Some(listen) = config.listen {
        Some(
            TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to bind {}", listen))?,
        )
    } else {
        None
    };

    #[cfg(feature = "tun")]
    let tun_enabled = config.tun.is_some();
    #[cfg(not(feature = "tun"))]
    let tun_enabled = false;
    info!(
        socks5_listen = ?config.listen,
        groups = registry.groups().len(),
        total_uplinks = registry.total_uplinks(),
        tun_enabled,
        "proxy started"
    );
    listener::warn_about_tcp_probe_target(&config);
    log_registry_summary(&registry);
    #[cfg(feature = "metrics")]
    if let Some(metrics) = config.metrics.clone() {
        spawn_metrics_server(metrics, registry.clone());
    }
    #[cfg(feature = "control")]
    if let Some(control) = config.control.clone() {
        spawn_control_server(control, registry.clone());
    }

    // Build the thin proxy-layer config slice from the fully-resolved AppConfig.
    // Each accepted connection clones only this Arc — not the full AppConfig —
    // so there is no unnecessary coupling to uplink/tun/metrics fields.
    let proxy_config = Arc::new(ProxyConfig {
        socks5_auth: config.socks5_auth.clone(),
        dns_cache: dns_cache.clone(),
        router: routing_table
            .clone()
            .map(|t| t as Arc<dyn crate::proxy::Router>),
        direct_fwmark: config.direct_fwmark,
        tcp_timeouts: config.tcp_timeouts,
    });

    let Some(listener) = listener else {
        // TUN-only mode: no TCP listener; block until shutdown signal.
        let mut rx = shutdown_rx;
        let _ = rx.wait_for(|&v| v).await;
        return Ok(());
    };

    listener::run_accept_loop(listener, proxy_config, registry, shutdown_rx).await
}
