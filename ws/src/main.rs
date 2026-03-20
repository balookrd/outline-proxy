use anyhow::Result;
use clap::Parser;

use outline_ws_rust::config::{Args, load_config};
use outline_ws_rust::memory::spawn_periodic_trim_loop;
use outline_ws_rust::metrics::{init as init_metrics, spawn_process_metrics_sampler};

#[tokio::main]
async fn main() -> Result<()> {
    outline_ws_rust::init_rustls_crypto_provider()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,outline_ws_rust=debug".into()),
        )
        .init();

    init_metrics();
    spawn_process_metrics_sampler();

    let args = Args::parse();
    let config = load_config(&args.config, &args).await?;
    if let Some(interval) = config.memory_trim_interval {
        spawn_periodic_trim_loop(interval);
    }
    outline_ws_rust::run_with_config(config).await
}
