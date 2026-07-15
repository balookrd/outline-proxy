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

    // Normalize the override-exclude suffixes once: lowercase + strip leading
    // dots / surrounding whitespace, drop empties. Shared by the TCP and QUIC
    // sniff paths (cheap Arc clone into both configs).
    let sniff_override_exclude: std::sync::Arc<[Box<str>]> = tun
        .and_then(|section| section.sniff_override_exclude.as_ref())
        .map(|list| {
            list.iter()
                .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .map(String::into_boxed_str)
                .collect::<Vec<_>>()
                .into()
        })
        .unwrap_or_else(|| Vec::new().into());

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
        // Per-flow downlink buffer soft limit. Downlink backpressure parks the
        // buffer here for the whole of a slow bulk download, so this is roughly
        // the committed RAM per saturated flow; the hard limit is
        // `backlog_hard_limit_multiplier`× it, so worst-case RSS is about
        // `max_flows × this × multiplier`. 2 MiB comfortably covers a fast
        // last-mile BDP (e.g. ~800 Mbit × 20 ms ≈ 2 MB) while keeping that
        // ceiling in check; raise it only for a high-bandwidth *and*
        // high-latency client link that cannot keep the pipe full otherwise.
        max_pending_server_bytes: tcp_section
            .and_then(|section| section.max_pending_server_bytes)
            .unwrap_or(2_097_152),
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
            .unwrap_or(2_097_152),
        max_retransmits: tcp_section.and_then(|section| section.max_retransmits).unwrap_or(12),
        downlink_max_rate_bps: tcp_section
            .and_then(|section| section.downlink_max_mbit)
            .map(|mbit| mbit.saturating_mul(1_000_000) / 8)
            .unwrap_or(0),
        keepalive_idle: tcp_section
            .and_then(|section| section.keepalive_idle_secs)
            .map(Duration::from_secs),
        keepalive_interval: Duration::from_secs(
            tcp_section
                .and_then(|section| section.keepalive_interval_secs)
                .unwrap_or(30),
        ),
        keepalive_max_probes: tcp_section
            .and_then(|section| section.keepalive_max_probes)
            .unwrap_or(6),
        sniffing: tcp_section.and_then(|section| section.sniffing).unwrap_or(true),
        sniff_timeout: Duration::from_millis(
            tcp_section
                .and_then(|section| section.sniff_timeout_ms)
                .unwrap_or(300),
        ),
        sniff_override_exclude: sniff_override_exclude.clone(),
        sniff_direct_reresolve: tcp_section
            .and_then(|section| section.sniff_direct_reresolve)
            .unwrap_or(false),
        // Default on: it costs nothing where it cannot help (a server without
        // resumption never issues a Session ID, so those flows are not even
        // eligible) and it only ever engages on a confirmed resume hit.
        carrier_migration: tcp_section
            .and_then(|section| section.carrier_migration)
            .unwrap_or(true),
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
    if tcp.max_buffered_client_bytes > 4_194_304 {
        bail!("tun.tcp.max_buffered_client_bytes must be at most 4194304");
    }
    if tcp.max_retransmits == 0 {
        bail!("tun.tcp.max_retransmits must be greater than zero");
    }
    if tcp.sniffing && tcp.sniff_timeout < Duration::from_millis(10) {
        bail!("tun.tcp.sniff_timeout_ms must be at least 10 when sniffing is enabled");
    }
    if let Some(idle) = tcp.keepalive_idle {
        if idle < Duration::from_secs(5) {
            bail!("tun.tcp.keepalive_idle_secs must be at least 5");
        }
        if tcp.keepalive_interval < Duration::from_secs(1) {
            bail!("tun.tcp.keepalive_interval_secs must be at least 1");
        }
        if tcp.keepalive_max_probes == 0 {
            bail!("tun.tcp.keepalive_max_probes must be greater than zero");
        }
    }

    #[cfg(target_os = "linux")]
    if name.is_none() {
        bail!("missing tun.name: Linux TUN attach requires --tun-name or [tun].name");
    }

    let ipsec_bypass = tun.and_then(|section| section.ipsec_bypass).unwrap_or(false);
    let pmtud_emit_below_quic_initial = tun
        .and_then(|section| section.pmtud_emit_below_quic_initial)
        .unwrap_or(false);
    let sniff_quic = tun.and_then(|section| section.sniff_quic).unwrap_or(true);
    let gso = tun.and_then(|section| section.gso).unwrap_or(false);
    let gro = tun.and_then(|section| section.gro).unwrap_or(false);
    if gro && !gso {
        bail!("tun.gro requires tun.gso (GRO needs the vnet header)");
    }
    // USO defaults to `gso`: with IFF_VNET_HDR the kernel frames a local app's
    // UDP-GSO (UDP_SEGMENT — the egress batching every QUIC/HTTP3 stack uses on
    // :443) as a GSO_UDP_L4 super-packet, only delivered intact when TUN_F_USO
    // is requested. Enabling `gso`/`gro` without USO leaves that path malformed
    // and breaks all UDP, so USO follows `gso` unless explicitly set to `false`
    // (a diagnostic escape hatch).
    let uso = tun.and_then(|section| section.uso).unwrap_or(gso);
    if uso && !gso {
        bail!("tun.uso requires tun.gso (USO needs the vnet header)");
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
        ipsec_bypass,
        pmtud_emit_below_quic_initial,
        sniff_quic,
        sniff_override_exclude,
        gso,
        gro,
        uso,
    }))
}
