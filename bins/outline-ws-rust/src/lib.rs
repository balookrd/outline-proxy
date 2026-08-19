//! outline-ws-rust — main binary crate.
//!
//! Wires together: configuration loading ([`config`]), startup and listener
//! binding (private `bootstrap` module), SOCKS5 TCP/UDP ingress ([`proxy`]),
//! and the optional read-only metrics and authenticated control-plane HTTP
//! listeners ([`http`]).

// Shared by the SOCKS5 accept loop and the HTTP listeners (metrics/control) —
// gated to whichever of those is compiled in, or the module goes unused.
#[cfg(any(feature = "socks5", feature = "metrics", feature = "control"))]
pub(crate) mod accept;
// error_class / client_io classify errors surfaced by `src/proxy` (SOCKS5
// ingress) and have no consumer outside it.
#[cfg(feature = "socks5")]
pub(crate) mod client_io;
pub mod config;
#[cfg(feature = "socks5")]
pub(crate) mod error_class;
// Hardened atomic config writer. Only the control plane rewrites config.toml,
// so it shares that feature's gate — otherwise a non-`control` build would flag
// it unused under `-D warnings`.
#[cfg(feature = "control")]
pub(crate) mod fs_util;
#[cfg(any(feature = "metrics", feature = "control"))]
pub mod http;
pub mod memory;
pub mod metrics;
#[cfg(feature = "socks5")]
pub mod proxy;
pub mod status;

mod bootstrap;

pub use bootstrap::run_with_config;
pub use status::{Carrier, CarrierStatus, active_carriers, clear_active_registry};

use std::os::fd::RawFd;

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

/// Runtime options that are NOT part of the persisted config — they belong to
/// the process lifecycle, not the TOML. Currently just the preopened TUN fd
/// handed in by an embedder (Android `VpnService`); desktop passes `None`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RunOptions {
    pub tun_fd: Option<RawFd>,
}

pub async fn run(args: Args) -> Result<()> {
    run_with_options(args, RunOptions::default()).await
}

pub async fn run_with_options(args: Args, opts: RunOptions) -> Result<()> {
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
    run_with_config(config, args, opts.tun_fd).await
}

#[cfg(test)]
#[path = "tests/run_options.rs"]
mod run_options_tests;
