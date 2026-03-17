pub mod config;
pub mod crypto;
pub mod metrics;
pub mod metrics_http;
pub mod memory;
pub mod proxy;
pub mod socks5;
pub mod transport;
pub mod tun;
pub mod tun_tcp;
pub mod types;
pub mod uplink;

#[cfg(feature = "allocator-jemalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context, Result, anyhow};
use rustls::crypto::ring;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::config::{AppConfig, Args, load_config};
use crate::metrics::{init as init_metrics, spawn_process_metrics_sampler};
use crate::metrics_http::spawn_metrics_server;
use crate::uplink::{UplinkManager, log_uplink_summary};

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
    run_with_config(config).await
}

pub async fn run_with_config(config: AppConfig) -> Result<()> {
    let uplinks = UplinkManager::new(
        config.uplinks.clone(),
        config.probe.clone(),
        config.load_balancing.clone(),
    )?;
    uplinks.spawn_probe_loop();
    uplinks.spawn_warm_standby_loop();
    uplinks.spawn_standby_keepalive_loop();

    if let Some(tun) = config.tun.clone() {
        crate::tun::spawn_tun_loop(tun, uplinks.clone())
            .await
            .context("failed to start TUN loop")?;
    }

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;

    info!(
        listen = %config.listen,
        uplinks = uplinks.uplinks().len(),
        tun_enabled = config.tun.is_some(),
        "proxy started"
    );
    log_uplink_summary(&uplinks);
    if let Some(metrics) = config.metrics.clone() {
        spawn_metrics_server(metrics, uplinks.clone());
    }

    loop {
        let (stream, peer) = listener.accept().await.context("accept failed")?;
        let config = config.clone();
        let uplinks = uplinks.clone();
        tokio::spawn(async move {
            if let Err(error) = proxy::handle_client(stream, peer, config, uplinks).await {
                if is_expected_client_disconnect(&error) {
                    debug!(%peer, error = %format!("{error:#}"), "connection closed by client");
                } else {
                    warn!(%peer, error = %format!("{error:#}"), "connection failed");
                }
            }
        });
    }
}

fn is_expected_client_disconnect(error: &anyhow::Error) -> bool {
    let lower = format!("{error:#}").to_lowercase();
    let client_side = lower.contains("client read failed") || lower.contains("client write failed");
    let disconnect = lower.contains("connection reset by peer")
        || lower.contains("broken pipe")
        || lower.contains("os error 104")
        || lower.contains("os error 54")
        || lower.contains("os error 32");
    client_side && disconnect
}
