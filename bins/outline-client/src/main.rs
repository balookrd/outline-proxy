use anyhow::Result;
use clap::Parser;

use outline_client::config::Args;

#[cfg(all(not(windows), feature = "jemalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read once at startup.
///
/// `background_thread` matters most: without it decay only advances when the
/// allocator is called, so a process that goes quiet right after a burst sits
/// on its high-water mark — the same trap that made mimalloc need a periodic
/// `mi_collect` here. `dirty_decay_ms` is the window before freed pages are
/// returned; 5 s trades a little reuse for RSS that follows load down.
/// `muzzy_decay_ms:0` returns the rest immediately rather than keeping a
/// second tier of half-released pages.
///
/// `calloc_madvise_threshold:0` keeps the jemalloc 5.3.0 behaviour for zeroed
/// allocations. Since 5.3.1 a `calloc` below the threshold (8 MiB by default)
/// served from reused dirty pages is zeroed with `memset`, which faults every
/// page of the buffer in; 5.3.0 purged those pages instead and left the buffer
/// lazily backed. Per-flow buffers are `vec![0; N]` and mostly idle, so on the
/// fleet the default doubled RSS (4 KiB-page aarch64 node: RSS/allocated 0.48 -> 1.06,
/// back to 0.40 with this set).
///
/// jemalloc applies `MALLOC_CONF` from the environment after this symbol, so a
/// node can retune without a rebuild.
#[cfg(all(not(windows), feature = "jemalloc"))]
#[unsafe(export_name = "malloc_conf")]
pub static MALLOC_CONF: &[u8] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:0,calloc_madvise_threshold:0\0";

fn main() -> Result<()> {
    outline_client::init_rustls_crypto_provider()?;

    // Integration-test hook (compiled out of production builds): trust a
    // self-signed root supplied by the e2e harness so the binary can dial
    // TLS / H3 carriers against a local test server. Installed
    // before any dial, since the rustls client-config cache captures the
    // root override on its first build.
    #[cfg(feature = "test-tls")]
    if let Ok(ca_path) = std::env::var("OUTLINE_WS_TEST_TLS_CA_DER") {
        let der = std::fs::read(&ca_path)?;
        outline_transport::install_test_tls_root(rustls::pki_types::CertificateDer::from(der));
    }

    let args = Args::parse();

    // Builds without the multi-thread feature have only the current_thread
    // scheduler (saves ~100–200 KB on MIPS). With multi-thread, the choice is
    // by --worker-threads: =1 → current_thread (avoids work-stealing
    // overhead), anything else → multi-thread.
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
                    .unwrap_or_else(|_| "info,outline_client=debug".into()),
            )
            .init();

        // Router builds: env-filter (regex, ~300 KB) is disabled.
        // Log level is fixed at WARN. Use a full build to get RUST_LOG support.
        #[cfg(not(feature = "env-filter"))]
        tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).init();

        #[cfg(all(unix, feature = "jemalloc"))]
        outline_client::memory::log_allocator_page_size();

        outline_client::run(args).await
    })
}

#[cfg(test)]
#[path = "tests/main.rs"]
mod tests;
