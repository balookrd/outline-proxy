use anyhow::Result;
use clap::Parser;

use outline_ws_rust::config::Args;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Period between forced mimalloc reclamation passes.
#[cfg(feature = "mimalloc")]
const MIMALLOC_PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Spawn a low-frequency background thread that forces mimalloc to return
/// decommittable memory to the OS.
///
/// mimalloc purges freed pages lazily, driven by allocator activity
/// (alloc/free traffic). A process that goes idle right after a large
/// transient burst — e.g. tens of thousands of TUN UDP flows created and
/// then drained together — can otherwise sit on its high-water-mark RSS
/// indefinitely, because nothing triggers the delayed purge. A periodic
/// `mi_collect(true)` forces that reclamation; a heap walk every 30 s is
/// negligible next to the RSS it returns. mimalloc already decommits on
/// purge by default (`mi_option_purge_decommits = 1`), so reclaimed pages
/// are handed back to the kernel rather than merely reset.
#[cfg(feature = "mimalloc")]
fn spawn_mimalloc_maintenance() {
    let spawned = std::thread::Builder::new()
        .name("mimalloc-purge".to_owned())
        .spawn(|| {
            loop {
                std::thread::sleep(MIMALLOC_PURGE_INTERVAL);
                // SAFETY: `mi_collect` is a thread-safe mimalloc entry point
                // with no preconditions. `force = true` reclaims empty
                // segments and returns decommitted memory to the OS.
                unsafe { libmimalloc_sys::mi_collect(true) };
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "failed to spawn mimalloc maintenance thread");
    }
}

fn main() -> Result<()> {
    outline_ws_rust::init_rustls_crypto_provider()?;

    let args = Args::parse();

    // Router builds compile without the multi-thread feature, so only the
    // current_thread scheduler is available (saves ~100–200 KB on MIPS).
    // Non-router builds choose based on --worker-threads: =1 → current_thread
    // (avoids work-stealing overhead), anything else → multi-thread.
    #[cfg(feature = "multi-thread")]
    let runtime = if args.worker_threads == Some(1) {
        tokio::runtime::Builder::new_current_thread().enable_all().build()?
    } else {
        let mut b = tokio::runtime::Builder::new_multi_thread();
        if let Some(n) = args.worker_threads {
            b.worker_threads(n);
        }
        if let Some(kb) = args.thread_stack_size_kb {
            b.thread_stack_size(kb * 1024);
        }
        b.enable_all().build()?
    };

    #[cfg(not(feature = "multi-thread"))]
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        #[cfg(feature = "env-filter")]
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,outline_ws_rust=debug".into()),
            )
            .init();

        // Router builds: env-filter (regex, ~300 KB) is disabled.
        // Log level is fixed at WARN. Use a full build to get RUST_LOG support.
        #[cfg(not(feature = "env-filter"))]
        tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).init();

        #[cfg(feature = "mimalloc")]
        spawn_mimalloc_maintenance();

        outline_ws_rust::run(args).await
    })
}
