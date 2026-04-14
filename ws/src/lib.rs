pub(crate) mod atomic_counter;
pub mod bypass;
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
pub mod socks5;
pub mod transport;
#[cfg(feature = "h3")]
#[path = "transport/h3.rs"]
pub(crate) mod transport_h3;
pub mod tun;
pub(crate) mod tun_defrag;
pub mod tun_tcp;
pub mod tun_udp;
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
use crate::uplink::{UplinkManager, log_uplink_summary};

fn warn_about_tcp_probe_target(config: &AppConfig) {
    let Some(tcp_probe) = config.probe.tcp.as_ref() else {
        return;
    };

    if matches!(tcp_probe.port, 80 | 443 | 8080 | 8443) {
        warn!(
            host = %tcp_probe.host,
            port = tcp_probe.port,
            "probe.tcp waits for the remote side to send bytes or close cleanly; HTTP/HTTPS-style targets on common web ports usually wait for a client request and will time out. Prefer probe.http for HTTP endpoints or use a speak-first TCP service for probe.tcp"
        );
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

pub async fn run_with_config(config: AppConfig) -> Result<()> {
    let uplinks = UplinkManager::new(
        config.uplinks.clone(),
        config.probe.clone(),
        config.load_balancing.clone(),
    )?;
    uplinks.initialize_strict_active_selection().await;
    uplinks.spawn_probe_loop();
    uplinks.spawn_warm_standby_loop();
    uplinks.spawn_standby_keepalive_loop();

    if let Some(tun) = config.tun.clone() {
        crate::tun::spawn_tun_loop(tun, uplinks.clone())
            .await
            .context("failed to start TUN loop")?;
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

    info!(
        socks5_listen = ?config.listen,
        uplinks = uplinks.uplinks().len(),
        tun_enabled = config.tun.is_some(),
        "proxy started"
    );
    warn_about_tcp_probe_target(&config);
    log_uplink_summary(&uplinks);
    #[cfg(feature = "metrics")]
    if let Some(metrics) = config.metrics.clone() {
        spawn_metrics_server(metrics, uplinks.clone());
    }

    let Some(listener) = listener else {
        std::future::pending::<()>().await;
        unreachable!("pending future never resolves");
    };

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // ECONNABORTED: the client withdrew the connection before
                // accept() returned.  This is harmless; just try again.
                if e.kind() == std::io::ErrorKind::ConnectionAborted {
                    continue;
                }
                // EMFILE / ENFILE: process or system FD limit reached.
                // Sleep briefly so that pending cleanup tasks (H2 driver
                // tasks, writer tasks) have a chance to run and free FDs,
                // then retry rather than propagating and killing the process.
                let raw = e.raw_os_error();
                if raw == Some(libc::EMFILE) || raw == Some(libc::ENFILE) {
                    warn!(error = %e, "accept failed (FD limit hit), backing off");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                return Err(e).context("accept failed");
            },
        };
        let config = config.clone();
        let uplinks = uplinks.clone();
        tokio::spawn(async move {
            if let Err(error) = proxy::handle_client(stream, peer, config, uplinks).await {
                if crate::error_text::is_expected_client_disconnect(&error) {
                    debug!(%peer, error = %format!("{error:#}"), "connection closed by client");
                } else {
                    warn!(%peer, error = %format!("{error:#}"), "connection failed");
                }
            }
        });
    }
}
