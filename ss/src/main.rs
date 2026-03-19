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
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
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
    start_memory_reclaimer(&config);
    server::run(config).await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("outline_ss_rust=info,tower_http=info"));
    fmt().with_env_filter(filter).compact().init();
}

#[cfg(target_os = "linux")]
fn start_memory_reclaimer(config: &Config) {
    if config.memory_trim_interval_secs == 0 {
        return;
    }

    let interval_secs = config.memory_trim_interval_secs;
    tracing::info!(
        memory_trim_interval_secs = interval_secs,
        "enabled periodic allocator memory trimming"
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let before = crate::metrics::process_memory_snapshot();
            match tokio::task::spawn_blocking(crate::metrics::trim_allocator).await {
                Ok(Ok(trim_hint)) => {
                    let after = crate::metrics::process_memory_snapshot();
                    let released_bytes = before
                        .zip(after)
                        .map(|(before, after)| {
                            before
                                .resident_memory_bytes
                                .saturating_sub(after.resident_memory_bytes)
                        })
                        .unwrap_or(0);
                    let release_event = trim_hint || released_bytes > 0;
                    crate::metrics::record_allocator_trim_run(before, after, release_event);

                    if release_event {
                        tracing::info!(
                            rss_before_bytes = before.map(|snapshot| snapshot.resident_memory_bytes),
                            rss_after_bytes = after.map(|snapshot| snapshot.resident_memory_bytes),
                            heap_before_bytes = before.and_then(|snapshot| snapshot.heap_allocated_bytes),
                            heap_after_bytes = after.and_then(|snapshot| snapshot.heap_allocated_bytes),
                            rss_released_bytes = released_bytes,
                            trim_hint,
                            "allocator memory trim released memory"
                        );
                    } else {
                        tracing::debug!(
                            rss_before_bytes = before.map(|snapshot| snapshot.resident_memory_bytes),
                            rss_after_bytes = after.map(|snapshot| snapshot.resident_memory_bytes),
                            heap_before_bytes = before.and_then(|snapshot| snapshot.heap_allocated_bytes),
                            heap_after_bytes = after.and_then(|snapshot| snapshot.heap_allocated_bytes),
                            trim_hint,
                            "allocator memory trim completed without observable RSS reduction"
                        );
                    }
                }
                Ok(Err(error)) => {
                    crate::metrics::record_allocator_trim_error();
                    tracing::warn!(?error, "allocator memory trim failed");
                }
                Err(error) => {
                    crate::metrics::record_allocator_trim_error();
                    tracing::warn!(?error, "allocator memory trim task failed");
                }
            }
        }
    });
}

#[cfg(not(target_os = "linux"))]
fn start_memory_reclaimer(config: &Config) {
    if config.memory_trim_interval_secs > 0 {
        tracing::warn!(
            memory_trim_interval_secs = config.memory_trim_interval_secs,
            "periodic allocator trimming is only supported on Linux"
        );
    }
}
