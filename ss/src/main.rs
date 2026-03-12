mod access_key;
mod config;
mod crypto;
mod protocol;
mod server;

use anyhow::Result;
use tracing_subscriber::{EnvFilter, fmt};

use crate::access_key::{build_access_key_artifacts, render_access_key_report};
use crate::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load()?;
    if config.print_access_keys {
        let artifacts = build_access_key_artifacts(&config)?;
        print!("{}", render_access_key_report(&artifacts));
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
