mod clock;
mod config;
mod crypto;
mod fwmark;
mod metrics;
mod outbound;
mod protocol;
mod server;

use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::AppMode;

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
    let AppMode::Serve(config) = AppMode::load()?;
    init_tracing();
    #[cfg(all(unix, feature = "jemalloc"))]
    metrics::log_allocator_page_size();
    server::run(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("outline_server=info,tower_http=info"));
    fmt().with_env_filter(filter).compact().init();
}
