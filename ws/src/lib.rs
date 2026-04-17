pub(crate) mod atomic_counter;
pub mod config;
pub mod crypto;
pub(crate) mod dns_cache;
pub(crate) mod error_text;
pub mod memory;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(not(feature = "metrics"))]
#[path = "metrics_stub.rs"]
pub mod metrics;
#[cfg(feature = "metrics")]
pub mod metrics_http;
pub mod proxy;
pub mod routing;
pub mod socks5;
pub mod transport;
#[cfg(feature = "h3")]
#[path = "transport/h3/mod.rs"]
pub(crate) mod transport_h3;
#[cfg(feature = "tun")]
pub mod tun;
#[cfg(feature = "tun")]
pub(crate) mod tun_defrag;
#[cfg(feature = "tun")]
pub mod tun_tcp;
#[cfg(feature = "tun")]
pub mod tun_udp;
#[cfg(feature = "tun")]
pub(crate) mod tun_wire;
pub mod types;
pub mod uplink;

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustls::crypto::ring;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::config::{AppConfig, Args, load_config};
use crate::metrics::{init as init_metrics, spawn_process_metrics_sampler};
#[cfg(feature = "metrics")]
use crate::metrics_http::spawn_metrics_server;
use crate::uplink::{StateStore, UplinkRegistry, log_registry_summary};

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
    transport::init_h2_window_sizes(
        config.h2.initial_stream_window_size,
        config.h2.initial_connection_window_size,
    );
    transport::init_udp_socket_bufs(config.udp_recv_buf_bytes, config.udp_send_buf_bytes);
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
    let registry = UplinkRegistry::new_with_state(config.groups.clone(), state_store).await?;
    registry.initialize_strict_active_selection().await;
    registry.spawn_probe_loops();
    registry.spawn_warm_standby_loops();
    registry.spawn_standby_keepalive_loops();

    // Compile the policy routing table (if user declared [[route]]) and
    // spawn per-rule file watchers for hot-reload.
    if let Some(routing_cfg) = config.routing.clone() {
        let table = std::sync::Arc::new(
            crate::routing::RoutingTable::compile(&routing_cfg)
                .await
                .context("failed to compile routing table")?,
        );
        crate::routing::spawn_route_watchers(std::sync::Arc::clone(&table));
        config.routing_table = Some(table);
    }

    // TUN dispatches through the policy routing table, falling back to the
    // default group when no [[route]] is configured.
    #[cfg(feature = "tun")]
    {
        let tun_routing = crate::tun::TunRouting::new(
            registry.clone(),
            config.routing_table.clone(),
            config.direct_fwmark,
        );

        if let Some(tun) = config.tun.clone() {
            crate::tun::spawn_tun_loop(tun, tun_routing)
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

    // Freeze config into an Arc so each accepted connection pays only a
    // pointer increment instead of a full deep clone.
    let config = std::sync::Arc::new(config);

    let Some(listener) = listener else {
        std::future::pending::<()>().await;
        unreachable!("pending future never resolves");
    };

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
        if let Err(error) = transport::configure_inbound_tcp_stream(&stream, peer) {
            debug!(%peer, error = %format!("{error:#}"), "failed to arm inbound TCP keepalive; proceeding without it");
        }
        let config = std::sync::Arc::clone(&config);
        let registry = registry.clone();
        tokio::spawn(async move {
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
