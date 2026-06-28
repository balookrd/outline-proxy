//! outline-ws-rust — main binary crate.
//!
//! Wires together: configuration loading ([`config`]), startup and listener
//! binding (private `bootstrap` module), SOCKS5 TCP/UDP ingress ([`proxy`]),
//! and the optional read-only metrics and authenticated control-plane HTTP
//! listeners ([`http`]).

pub(crate) mod client_io;
pub mod config;
pub(crate) mod error_class;
#[cfg(any(feature = "metrics", feature = "control", feature = "dashboard"))]
pub mod http;
pub mod memory;
pub mod metrics;
pub mod proxy;
#[cfg(feature = "h3")]
pub(crate) mod reverse;

mod bootstrap;

pub use bootstrap::run_with_config;

use anyhow::{Result, anyhow};
use rustls::crypto::aws_lc_rs;

use crate::config::{Args, load_config};
use crate::metrics::{init as init_metrics, spawn_process_metrics_sampler};

pub fn init_rustls_crypto_provider() -> Result<()> {
    let provider = aws_lc_rs::default_provider();
    match provider.install_default() {
        Ok(()) => Ok(()),
        Err(_) if rustls::crypto::CryptoProvider::get_default().is_some() => Ok(()),
        Err(_) => Err(anyhow!("failed to install rustls aws-lc-rs CryptoProvider")),
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
    #[cfg(feature = "h3")]
    outline_transport::init_quic_window_sizes(
        config.quic.stream_receive_window,
        config.quic.receive_window,
    );
    outline_net::init_udp_socket_bufs(config.udp_recv_buf_bytes, config.udp_send_buf_bytes);
    outline_net::init_prefer_public_ipv6_src(config.prefer_public_ipv6_src.unwrap_or(true));
    outline_net::init_direct_ipv6_prefix_iface(config.direct_ipv6_prefix_interface.clone());
    run_with_config(config, args).await
}
