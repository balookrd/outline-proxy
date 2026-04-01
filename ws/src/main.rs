use anyhow::Result;
use clap::Parser;

use outline_ws_rust::config::Args;

fn main() -> Result<()> {
    outline_ws_rust::init_rustls_crypto_provider()?;

    let args = Args::parse();

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(n) = args.worker_threads {
        builder.worker_threads(n);
    }
    builder.enable_all().build()?.block_on(async move {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,outline_ws_rust=debug".into()),
            )
            .init();

        outline_ws_rust::run(args).await
    })
}
