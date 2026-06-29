//! Android (JNI/UniFFI) wrapper around the `outline-ws-rust` client.
//!
//! Exposes a tiny lifecycle API (`start` / `stop` / `is_running`) that the
//! Kotlin `VpnService` drives. `start` writes the supplied TOML to the app's
//! working directory, boots the full ws-rust client — SOCKS5 ingress plus the
//! WS/TLS/VLESS/SS uplink stack with padding and failover — and bridges the
//! `VpnService` TUN descriptor into that SOCKS5 listener via `tun2proxy`.
//!
//! Loop avoidance: the uplink sockets ws-rust opens to your servers must NOT
//! re-enter the tunnel. Rather than threading a per-socket `VpnService.protect`
//! callback through the whole dial path, the Kotlin side excludes this app's
//! own package from the VPN (`addDisallowedApplication`), so every socket this
//! process creates bypasses the TUN automatically.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tracing::{error, info};
use tun2proxy::{ArgProxy, Args as TunArgs, CancellationToken};

uniffi::setup_scaffolding!("outline_android");

/// TUN MTU. Must match `VpnService.Builder.setMtu` on the Kotlin side.
const TUN_MTU: u16 = 1500;

/// Errors surfaced across the FFI boundary to Kotlin.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VpnError {
    #[error("client is already running")]
    AlreadyRunning,
    #[error("client is not running")]
    NotRunning,
    #[error("configuration error: {msg}")]
    Config { msg: String },
    #[error("runtime error: {msg}")]
    Runtime { msg: String },
}

/// A running client instance: the dedicated runtime, the join handles of the
/// ws-rust client task and the tun2proxy bridge task, and the token that stops
/// the bridge.
struct Engine {
    runtime: Runtime,
    client_task: JoinHandle<()>,
    bridge_task: JoinHandle<()>,
    shutdown: CancellationToken,
}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

/// Best-effort one-time logging setup. On Android, `tracing` is routed into
/// logcat (tag `OutlineProxy`) via paranoid-android; elsewhere it goes to the
/// plain fmt subscriber. Failures here are non-fatal.
#[cfg(target_os = "android")]
fn init_logging() {
    use std::sync::Once;
    use tracing_subscriber::prelude::*;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let layer = paranoid_android::layer("OutlineProxy")
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO);
        let _ = tracing_subscriber::registry().with(layer).try_init();
    });
}

#[cfg(not(target_os = "android"))]
fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    });
}

/// Start the client and the TUN bridge.
///
/// * `config_toml` — full ws-rust client config (uplinks, transport, SOCKS5
///   listen address, padding, routing). Written verbatim to
///   `{work_dir}/config.toml`. The `[socks5] listen` address must match
///   `socks_proxy_url`.
/// * `work_dir` — an app-private writable directory (e.g. `Context.filesDir`).
/// * `tun_fd` — the TUN file descriptor from `VpnService.establish()`. tun2proxy
///   reads/writes it but does NOT close it on drop; the Kotlin side owns the
///   `ParcelFileDescriptor` lifetime.
/// * `socks_proxy_url` — where the ws-rust SOCKS5 listener is reachable, e.g.
///   `socks5://127.0.0.1:1080`.
#[uniffi::export]
pub fn start(
    config_toml: String,
    work_dir: String,
    tun_fd: i32,
    socks_proxy_url: String,
) -> Result<(), VpnError> {
    init_logging();

    let mut guard = ENGINE.lock().expect("ENGINE mutex poisoned");
    if guard.is_some() {
        return Err(VpnError::AlreadyRunning);
    }

    // rustls' aws-lc-rs CryptoProvider must be installed before any TLS work.
    outline_ws_rust::init_rustls_crypto_provider()
        .map_err(|e| VpnError::Runtime { msg: format!("crypto provider: {e:#}") })?;

    let cfg_path = PathBuf::from(&work_dir).join("config.toml");
    std::fs::write(&cfg_path, config_toml)
        .map_err(|e| VpnError::Config { msg: format!("write {}: {e}", cfg_path.display()) })?;

    // Build ws-rust's CLI args from the config path; every other field falls
    // back to its clap default / env. `try_parse_from` never panics across FFI.
    let cfg_arg = cfg_path.to_string_lossy().into_owned();
    let client_args = outline_ws_rust::config::Args::try_parse_from([
        "outline-ws-rust",
        "--config",
        &cfg_arg,
    ])
    .map_err(|e| VpnError::Config { msg: format!("args: {e}") })?;

    // tun2proxy configuration: forward the TUN fd into the local SOCKS5 proxy.
    let proxy = ArgProxy::try_from(socks_proxy_url.as_str())
        .map_err(|e| VpnError::Config { msg: format!("proxy url: {e}") })?;
    let mut bridge_args = TunArgs::default();
    bridge_args.proxy = proxy;
    bridge_args.tun_fd = Some(tun_fd);
    // Kotlin owns the ParcelFileDescriptor — do not close it from here.
    bridge_args.close_fd_on_drop = Some(false);
    bridge_args.mtu = TUN_MTU;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| VpnError::Runtime { msg: format!("tokio runtime: {e}") })?;

    info!(tun_fd, %cfg_arg, %socks_proxy_url, "starting outline-ws-rust client + TUN bridge");

    // ws-rust client (SOCKS5 listener + uplinks).
    let client_task = runtime.spawn(async move {
        if let Err(e) = outline_ws_rust::run(client_args).await {
            error!("client exited with error: {e:#}");
        }
    });

    // tun2proxy bridge, cancellable via the shutdown token.
    let shutdown = CancellationToken::new();
    let bridge_shutdown = shutdown.clone();
    let bridge_task = runtime.spawn(async move {
        match tun2proxy::general_run_async(bridge_args, TUN_MTU, false, bridge_shutdown).await {
            Ok(_) => info!("tun2proxy bridge stopped"),
            Err(e) => error!("tun2proxy bridge error: {e}"),
        }
    });

    *guard = Some(Engine { runtime, client_task, bridge_task, shutdown });
    Ok(())
}

/// Stop the client and the bridge, then tear down the runtime. Returns
/// `NotRunning` if nothing is active.
#[uniffi::export]
pub fn stop() -> Result<(), VpnError> {
    let mut guard = ENGINE.lock().expect("ENGINE mutex poisoned");
    match guard.take() {
        Some(engine) => {
            // Stop the bridge gracefully, then the client, then the runtime.
            engine.shutdown.cancel();
            engine.bridge_task.abort();
            engine.client_task.abort();
            engine.runtime.shutdown_timeout(Duration::from_secs(2));
            info!("client stopped");
            Ok(())
        },
        None => Err(VpnError::NotRunning),
    }
}

/// Whether a client instance is currently running.
#[uniffi::export]
pub fn is_running() -> bool {
    ENGINE.lock().expect("ENGINE mutex poisoned").is_some()
}
