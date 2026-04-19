use std::time::Duration;

use anyhow::{Result, anyhow, bail};

use outline_tun::{TunConfig, TunTcpConfig};

use super::super::args::Args;
use super::super::schema::TunSection;

pub(super) fn load_tun_config(tun: Option<&TunSection>, args: &Args) -> Result<Option<TunConfig>> {
    let path = args
        .tun_path
        .clone()
        .or_else(|| tun.and_then(|section| section.path.clone()));
    let name = args
        .tun_name
        .clone()
        .or_else(|| tun.and_then(|section| section.name.clone()));
    let mtu = args
        .tun_mtu
        .or_else(|| tun.and_then(|section| section.mtu))
        .unwrap_or(1500);
    let max_flows = tun.and_then(|section| section.max_flows).unwrap_or(4096);
    let idle_timeout =
        Duration::from_secs(tun.and_then(|section| section.idle_timeout_secs).unwrap_or(300));

    if path.is_none() && name.is_none() {
        return Ok(None);
    }

    let path =
        path.ok_or_else(|| anyhow!("missing tun.path: set it in config.toml or pass --tun-path"))?;

    if mtu < 1280 {
        bail!("tun mtu must be at least 1280");
    }
    if max_flows == 0 {
        bail!("tun max_flows must be greater than zero");
    }
    if idle_timeout < Duration::from_secs(5) {
        bail!("tun idle_timeout_secs must be at least 5");
    }

    let tcp_section = tun.and_then(|section| section.tcp.as_ref());
    let tcp = TunTcpConfig {
        connect_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.connect_timeout_secs)
                .unwrap_or(10),
        ),
        handshake_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.handshake_timeout_secs)
                .unwrap_or(15),
        ),
        half_close_timeout: Duration::from_secs(
            tcp_section
                .and_then(|section| section.half_close_timeout_secs)
                .unwrap_or(60),
        ),
        max_pending_server_bytes: tcp_section
            .and_then(|section| section.max_pending_server_bytes)
            .unwrap_or(4_194_304),
        backlog_abort_grace: Duration::from_secs(
            tcp_section
                .and_then(|section| section.backlog_abort_grace_secs)
                .unwrap_or(3),
        ),
        backlog_hard_limit_multiplier: tcp_section
            .and_then(|section| section.backlog_hard_limit_multiplier)
            .unwrap_or(2),
        backlog_no_progress_abort: Duration::from_secs(
            tcp_section
                .and_then(|section| section.backlog_no_progress_abort_secs)
                .unwrap_or(8),
        ),
        max_buffered_client_segments: tcp_section
            .and_then(|section| section.max_buffered_client_segments)
            .unwrap_or(4096),
        max_buffered_client_bytes: tcp_section
            .and_then(|section| section.max_buffered_client_bytes)
            .unwrap_or(262_144),
        max_retransmits: tcp_section.and_then(|section| section.max_retransmits).unwrap_or(12),
    };
    if tcp.connect_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.connect_timeout_secs must be at least 1");
    }
    if tcp.handshake_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.handshake_timeout_secs must be at least 1");
    }
    if tcp.half_close_timeout < Duration::from_secs(1) {
        bail!("tun.tcp.half_close_timeout_secs must be at least 1");
    }
    if tcp.max_pending_server_bytes < 16_384 {
        bail!("tun.tcp.max_pending_server_bytes must be at least 16384");
    }
    if tcp.backlog_abort_grace < Duration::from_secs(1) {
        bail!("tun.tcp.backlog_abort_grace_secs must be at least 1");
    }
    if tcp.backlog_hard_limit_multiplier < 2 {
        bail!("tun.tcp.backlog_hard_limit_multiplier must be at least 2");
    }
    if tcp.backlog_no_progress_abort < Duration::from_secs(1) {
        bail!("tun.tcp.backlog_no_progress_abort_secs must be at least 1");
    }
    if tcp.max_buffered_client_segments == 0 {
        bail!("tun.tcp.max_buffered_client_segments must be greater than zero");
    }
    if tcp.max_buffered_client_bytes < 16_384 {
        bail!("tun.tcp.max_buffered_client_bytes must be at least 16384");
    }
    if tcp.max_buffered_client_bytes > 262_144 {
        bail!("tun.tcp.max_buffered_client_bytes must be at most 262144");
    }
    if tcp.max_retransmits == 0 {
        bail!("tun.tcp.max_retransmits must be greater than zero");
    }

    #[cfg(target_os = "linux")]
    if name.is_none() {
        bail!("missing tun.name: Linux TUN attach requires --tun-name or [tun].name");
    }

    let defrag_max_fragment_sets = tun
        .and_then(|section| section.defrag_max_fragment_sets)
        .unwrap_or(1024);
    let defrag_max_fragments_per_set = tun
        .and_then(|section| section.defrag_max_fragments_per_set)
        .unwrap_or(64);
    let defrag_max_total_bytes = tun
        .and_then(|section| section.defrag_max_total_bytes)
        .unwrap_or(16 * 1024 * 1024);
    let defrag_max_bytes_per_set = tun
        .and_then(|section| section.defrag_max_bytes_per_set)
        .unwrap_or(128 * 1024);
    if defrag_max_fragment_sets == 0 {
        bail!("tun.defrag_max_fragment_sets must be greater than zero");
    }
    if defrag_max_fragments_per_set == 0 {
        bail!("tun.defrag_max_fragments_per_set must be greater than zero");
    }
    if defrag_max_total_bytes < 64 * 1024 {
        bail!("tun.defrag_max_total_bytes must be at least 65536");
    }
    if defrag_max_bytes_per_set < 1500 {
        bail!("tun.defrag_max_bytes_per_set must be at least 1500");
    }
    if defrag_max_bytes_per_set > defrag_max_total_bytes {
        bail!("tun.defrag_max_bytes_per_set must not exceed tun.defrag_max_total_bytes");
    }

    Ok(Some(TunConfig {
        path,
        name,
        mtu,
        max_flows,
        idle_timeout,
        tcp,
        defrag_max_fragment_sets,
        defrag_max_fragments_per_set,
        defrag_max_total_bytes,
        defrag_max_bytes_per_set,
    }))
}
