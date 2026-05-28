mod clock;
mod config;
mod crypto;
mod fs_util;
mod fwmark;
mod metrics;
mod outbound;
mod protocol;
mod server;

use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::access_key::{
    build_access_key_artifacts, render_access_key_report, render_written_access_key_report,
    write_access_key_artifacts,
};
use crate::config::{AppMode, migrate_config_in_place};

#[cfg(target_os = "linux")]
const DEFAULT_RUNTIME_THREAD_STACK_SIZE_BYTES: usize = 2 * 1024 * 1024;

pub fn run() -> Result<()> {
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();
    configure_runtime_defaults(&mut runtime_builder);
    let runtime = runtime_builder.build()?;
    runtime.block_on(async_main())
}

#[cfg(target_os = "linux")]
fn configure_runtime_defaults(builder: &mut tokio::runtime::Builder) {
    // Avoid inheriting oversized per-thread stack reservations from the host
    // environment (for example 64 MiB pthread stacks), which show up as large
    // anonymous virtual memory mappings on long-lived services.
    builder.thread_stack_size(DEFAULT_RUNTIME_THREAD_STACK_SIZE_BYTES);
}

#[cfg(not(target_os = "linux"))]
fn configure_runtime_defaults(_builder: &mut tokio::runtime::Builder) {}

async fn async_main() -> Result<()> {
    match AppMode::load()? {
        AppMode::Serve(config) => {
            init_tracing();
            spawn_mimalloc_maintenance();
            server::run(config).await
        },
        AppMode::MigrateConfig { path } => {
            let changed = migrate_config_in_place(&path)?;
            if changed {
                println!("migrated {} (backup written alongside)", path.display());
            } else {
                println!("{} already uses the new layout; nothing to do", path.display());
            }
            Ok(())
        },
        AppMode::GenerateKeys { config, access_key, print, write_dir } => {
            let artifacts = build_access_key_artifacts(&config, &access_key)?;
            if print {
                print!("{}", render_access_key_report(&artifacts));
            }
            if let Some(output_dir) = &write_dir {
                let written = write_access_key_artifacts(&artifacts, output_dir)?;
                if print {
                    println!();
                }
                print!("{}", render_written_access_key_report(&written));
            }
            Ok(())
        },
    }
}

/// Period between forced mimalloc reclamation passes.
const MIMALLOC_PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Spawn a low-frequency background thread that forces mimalloc to return
/// decommittable memory to the OS.
///
/// mimalloc purges freed pages lazily, driven by allocator activity
/// (alloc/free traffic). A process that goes idle right after a large
/// transient burst — e.g. tens of thousands of UDP/NAT sessions created and
/// then drained together — can otherwise sit on its high-water-mark RSS
/// indefinitely, because nothing triggers the delayed purge. A periodic
/// `mi_collect(true)` forces that reclamation; a heap walk every 30 s is
/// negligible next to the RSS it returns. mimalloc already decommits on
/// purge by default (`mi_option_purge_decommits = 1`), so reclaimed pages
/// are handed back to the kernel rather than merely reset.
fn spawn_mimalloc_maintenance() {
    let spawned = std::thread::Builder::new()
        .name("mimalloc-purge".to_owned())
        .spawn(|| {
            loop {
                std::thread::sleep(MIMALLOC_PURGE_INTERVAL);
                // SAFETY: `mi_collect` is a thread-safe mimalloc entry point with no
                // preconditions. `force = true` reclaims empty segments and returns
                // decommitted memory to the OS.
                unsafe { libmimalloc_sys::mi_collect(true) };
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "failed to spawn mimalloc maintenance thread");
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("outline_ss_rust=info,tower_http=info"));
    fmt().with_env_filter(filter).compact().init();
}
