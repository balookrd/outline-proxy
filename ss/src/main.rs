mod access_key;
mod config;
mod crypto;
mod fwmark;
mod metrics;
mod nat;
mod protocol;
mod server;

use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt};

use crate::access_key::{
    build_access_key_artifacts, render_access_key_report, render_written_access_key_report,
    write_access_key_artifacts,
};
use crate::config::Config;

#[cfg(target_os = "linux")]
const DEFAULT_RUNTIME_THREAD_STACK_SIZE_BYTES: usize = 2 * 1024 * 1024;

fn main() -> Result<()> {
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
    let config = Config::load()?;
    if config.print_access_keys || config.write_access_keys_dir.is_some() {
        let artifacts = build_access_key_artifacts(&config)?;
        if config.print_access_keys {
            print!("{}", render_access_key_report(&artifacts));
        }
        if let Some(output_dir) = &config.write_access_keys_dir {
            let written = write_access_key_artifacts(&artifacts, output_dir)?;
            if config.print_access_keys {
                println!();
            }
            print!("{}", render_written_access_key_report(&written));
        }
        return Ok(());
    }

    init_tracing();
    server::run(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("outline_ss_rust=info,tower_http=info"));
    fmt().with_env_filter(filter).compact().init();
}
