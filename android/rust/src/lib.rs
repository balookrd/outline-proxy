//! Android (JNI/UniFFI) wrapper around the `outline-ws-rust` client.
//!
//! Exposes a tiny lifecycle API (`start` / `stop` / `is_running`) that the
//! Kotlin `VpnService` drives. `start` writes the supplied TOML to the app's
//! working directory and boots the full ws-rust client — the native
//! `outline-tun` engine attached to the `VpnService` TUN fd, plus the
//! WS/TLS/VLESS/SS uplink stack with padding and failover. No SOCKS5 listener
//! and no tun2proxy bridge: the TUN fd is driven natively via
//! `RunOptions.tun_fd`.
//!
//! Loop avoidance: the uplink sockets ws-rust opens must NOT re-enter the
//! tunnel. The Kotlin side excludes this app's own package from the VPN
//! (`addDisallowedApplication`), so every socket this process creates bypasses
//! the TUN automatically — no per-socket `VpnService.protect` needed.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use outline_ws_rust::RunOptions;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tracing::{error, info};

uniffi::setup_scaffolding!("outline_android");

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

/// A running client instance: the dedicated runtime and the join handle of the
/// ws-rust client task (SOCKS5 is off — the native TUN engine carries traffic).
struct Engine {
    runtime: Runtime,
    client_task: JoinHandle<()>,
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

/// Start the client with the native TUN engine bound to `tun_fd`.
///
/// * `config_toml` — full ws-rust client config. MUST contain a `[tun]` section
///   with a placeholder `path` (e.g. `path = "vpn"`) so the loader activates
///   TUN; the fd itself is injected here, not via the TOML.
/// * `work_dir` — an app-private writable directory (e.g. `Context.filesDir`).
/// * `tun_fd` — the TUN fd from `VpnService.establish()`. We `dup` it inside
///   the engine; the Kotlin side keeps owning the `ParcelFileDescriptor`.
#[uniffi::export]
pub fn start(config_toml: String, work_dir: String, tun_fd: i32) -> Result<(), VpnError> {
    init_logging();

    let mut guard = ENGINE.lock().expect("ENGINE mutex poisoned");
    if guard.is_some() {
        return Err(VpnError::AlreadyRunning);
    }

    outline_ws_rust::init_rustls_crypto_provider()
        .map_err(|e| VpnError::Runtime { msg: format!("crypto provider: {e:#}") })?;

    let cfg_path = PathBuf::from(&work_dir).join("config.toml");
    std::fs::write(&cfg_path, config_toml).map_err(|e| VpnError::Config {
        msg: format!("write {}: {e}", cfg_path.display()),
    })?;

    let cfg_arg = cfg_path.to_string_lossy().into_owned();
    let client_args =
        outline_ws_rust::config::Args::try_parse_from(["outline-ws-rust", "--config", &cfg_arg])
            .map_err(|e| VpnError::Config { msg: format!("args: {e}") })?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| VpnError::Runtime { msg: format!("tokio runtime: {e}") })?;

    info!(tun_fd, %cfg_arg, "starting outline-ws-rust client with native TUN");

    let opts = RunOptions { tun_fd: Some(tun_fd) };
    let client_task = runtime.spawn(async move {
        if let Err(e) = outline_ws_rust::run_with_options(client_args, opts).await {
            error!("client exited with error: {e:#}");
        }
    });

    *guard = Some(Engine { runtime, client_task });
    Ok(())
}

/// Stop the client and tear down the runtime. Returns `NotRunning` if nothing
/// is active.
#[uniffi::export]
pub fn stop() -> Result<(), VpnError> {
    let mut guard = ENGINE.lock().expect("ENGINE mutex poisoned");
    match guard.take() {
        Some(engine) => {
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
