use anyhow::Result;
use clap::Parser;

use outline_ws_rust::config::Args;

#[tokio::main]
async fn main() -> Result<()> {
    outline_ws_rust::init_rustls_crypto_provider()?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,outline_ws_rust=debug".into()),
        )
        .init();

    let args = Args::parse();
    outline_ws_rust::run(args).await
}
