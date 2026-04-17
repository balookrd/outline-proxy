use anyhow::Result;
use clap::Parser;

use outline_ws_rust::config::Args;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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

        outline_ws_rust::run(args).await
    })
}
