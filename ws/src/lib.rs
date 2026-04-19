pub mod config;
pub(crate) mod error_text;
pub mod memory;
pub mod metrics;
#[cfg(feature = "metrics")]
pub mod metrics_http;
pub mod proxy;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustls::crypto::ring;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::config::{AppConfig, Args, load_config};
use crate::metrics::{init as init_metrics, spawn_process_metrics_sampler};
#[cfg(feature = "metrics")]
use crate::metrics_http::spawn_metrics_server;
use crate::proxy::ProxyConfig;
use outline_uplink::{StateStore, UplinkRegistry, log_registry_summary};

fn warn_about_tcp_probe_target(config: &AppConfig) {
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

pub fn init_rustls_crypto_provider() -> Result<()> {
    let provider = ring::default_provider();
    match provider.install_default() {
        Ok(()) => Ok(()),
        Err(_) if rustls::crypto::CryptoProvider::get_default().is_some() => Ok(()),
        Err(_) => Err(anyhow!("failed to install rustls ring CryptoProvider")),
    }
}

pub async fn run(args: Args) -> Result<()> {
    init_metrics();
    spawn_process_metrics_sampler();
    let config = load_config(&args.config, &args).await?;
    outline_transport::init_h2_window_sizes(
        config.h2.initial_stream_window_size,
        config.h2.initial_connection_window_size,
    );
    outline_transport::init_udp_socket_bufs(config.udp_recv_buf_bytes, config.udp_send_buf_bytes);
    run_with_config(config).await
}

pub async fn run_with_config(mut config: AppConfig) -> Result<()> {
    // Load (or create) the persistent state store, then build the registry
    // with restored active-uplink selections.
    let state_store = if let Some(path) = config.state_path.clone() {
        // Probe write access before committing to the path.  On many
        // deployments the config lives in /etc/ (owned by root) while the
        // proxy runs as an unprivileged user — fail clearly instead of
        // silently dropping every write later.
        let probe = {
            let mut opts = tokio::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(false);
            // Restrict newly created state files to the process owner.
            // The file contains uplink names; readable-by-all is harmless
            // but there's no reason to be permissive.
            // tokio::fs::OpenOptions exposes mode() as an inherent method on Unix.
            #[cfg(unix)]
            opts.mode(0o600);
            opts.open(&path).await
        };
        match probe {
            Ok(_) => {
                let store: std::sync::Arc<StateStore> =
                    StateStore::load_or_default(path).await;
                store.clone().spawn_writer();
                Some(store)
            },
            Err(e) => {
                warn!(
                    path = ?path,
                    error = %e,
                    "cannot write uplink state file — active-uplink selection \
                     will not persist across restarts. \
                     Fix permissions or point state_path to a writable location."
                );
                None
            },
        }
    } else {
        None
    };
    // Shared DNS cache used by every transport resolve path. Owned by
    // AppConfig so the runtime paths receive the same Arc<DnsCache>.
    config.dns_cache = Some(std::sync::Arc::new(
        outline_transport::DnsCache::new(outline_transport::DEFAULT_DNS_CACHE_TTL),
    ));
    let dns_cache = config
        .dns_cache
        .clone()
        .expect("dns_cache just initialised");
    let registry =
        UplinkRegistry::new_with_state(config.groups.clone(), state_store, dns_cache.clone()).await?;
    registry.initialize_strict_active_selection().await;
    registry.spawn_probe_loops();
    registry.spawn_warm_standby_loops();
    registry.spawn_standby_keepalive_loops();
    registry.spawn_shared_connection_gc_loop();

    // Compile the policy routing table (if user declared [[route]]) and
    // spawn per-rule file watchers for hot-reload.
    if let Some(routing_cfg) = config.routing.clone() {
        let table = std::sync::Arc::new(
            outline_routing::RoutingTable::compile(&routing_cfg)
                .await
                .context("failed to compile routing table")?,
        );
        outline_routing::spawn_route_watchers(std::sync::Arc::clone(&table));
        config.routing_table = Some(table);
    }

    // TUN dispatches through the policy routing table, falling back to the
    // default group when no [[route]] is configured.
    #[cfg(feature = "tun")]
    {
        let tun_routing = outline_tun::TunRouting::new(
            registry.clone(),
            config.routing_table.clone(),
            config.direct_fwmark,
        );

        if let Some(tun) = config.tun.clone() {
            let tun_dns_cache = config
                .dns_cache
                .clone()
                .expect("dns_cache initialised above");
            outline_tun::spawn_tun_loop(tun, tun_routing, tun_dns_cache)
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
    warn_about_tcp_probe_target(&config);
    log_registry_summary(&registry);
    #[cfg(feature = "metrics")]
    if let Some(metrics) = config.metrics.clone() {
        spawn_metrics_server(metrics, registry.clone());
    }

    // Build the thin proxy-layer config slice from the fully-resolved AppConfig.
    // Each accepted connection clones only this Arc — not the full AppConfig —
    // so there is no unnecessary coupling to uplink/tun/metrics fields.
    let proxy_config = std::sync::Arc::new(ProxyConfig {
        socks5_auth: config.socks5_auth.clone(),
        dns_cache: dns_cache.clone(),
        routing_table: config.routing_table.clone(),
        direct_fwmark: config.direct_fwmark,
    });

    let Some(listener) = listener else {
        std::future::pending::<()>().await;
        unreachable!("pending future never resolves");
    };

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
