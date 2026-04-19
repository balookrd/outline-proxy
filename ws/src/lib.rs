//! outline-ws-rust — main binary crate.
//!
//! Wires together: configuration loading ([`config`]), startup and listener
//! binding ([`bootstrap`]), SOCKS5 TCP/UDP ingress ([`proxy`]), and the
//! optional Prometheus metrics HTTP endpoint ([`metrics_http`]).

pub mod config;
pub(crate) mod client_io;
pub(crate) mod error_text;
pub mod memory;
pub mod metrics;
#[cfg(feature = "metrics")]
pub mod metrics_http;
pub mod proxy;

mod bootstrap;

pub use bootstrap::run_with_config;

use anyhow::{Result, anyhow};
use rustls::crypto::ring;

use crate::config::{Args, load_config};
use crate::metrics::{init as init_metrics, spawn_process_metrics_sampler};

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
