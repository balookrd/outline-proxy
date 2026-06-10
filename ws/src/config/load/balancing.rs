use std::time::Duration;

use anyhow::{Result, bail};

use outline_uplink::{
    LoadBalancingConfig, LoadBalancingMode, OverflowPolicy, RoutingScope, VlessUdpMuxLimits,
};

use super::super::schema::LoadBalancingSection;

pub(super) fn load_balancing_config(
    lb: Option<&LoadBalancingSection>,
) -> Result<LoadBalancingConfig> {
    let rtt_ewma_alpha = lb.and_then(|l| l.rtt_ewma_alpha).unwrap_or(0.3);
    if !(rtt_ewma_alpha.is_finite() && 0.0 < rtt_ewma_alpha && rtt_ewma_alpha <= 1.0) {
        bail!("load_balancing.rtt_ewma_alpha must be in the range (0, 1]");
    }
    Ok(LoadBalancingConfig {
        mode: lb.and_then(|l| l.mode).unwrap_or(LoadBalancingMode::ActiveActive),
        routing_scope: lb.and_then(|l| l.routing_scope).unwrap_or(RoutingScope::PerFlow),
        sticky_ttl: Duration::from_secs(lb.and_then(|l| l.sticky_ttl_secs).unwrap_or(300)),
        hysteresis: Duration::from_millis(lb.and_then(|l| l.hysteresis_ms).unwrap_or(50)),
        failure_cooldown: Duration::from_secs(
            lb.and_then(|l| l.failure_cooldown_secs).unwrap_or(10),
        ),
        tcp_chunk0_failover_timeout: Duration::from_secs(
            lb.and_then(|l| l.tcp_chunk0_failover_timeout_secs).unwrap_or(10),
        ),
        warm_standby_tcp: lb.and_then(|l| l.warm_standby_tcp).unwrap_or(0),
        warm_standby_udp: lb.and_then(|l| l.warm_standby_udp).unwrap_or(0),
        rtt_ewma_alpha,
        failure_penalty: Duration::from_millis(
            lb.and_then(|l| l.failure_penalty_ms).unwrap_or(500),
        ),
        failure_penalty_max: Duration::from_millis(
            lb.and_then(|l| l.failure_penalty_max_ms).unwrap_or(30_000),
        ),
        failure_penalty_halflife: Duration::from_secs(
            lb.and_then(|l| l.failure_penalty_halflife_secs).unwrap_or(60),
        ),
        mode_downgrade_duration: Duration::from_secs(
            lb.and_then(|l| l.mode_downgrade_secs).unwrap_or(60),
        ),
        runtime_failure_window: Duration::from_secs(
            lb.and_then(|l| l.runtime_failure_window_secs).unwrap_or(60),
        ),
        // Default: 5 minutes — wide enough that sparse but recurring
        // chunk-0 timeouts (one every couple of minutes — the typical
        // signature of a silently-degraded upstream) accumulate to the
        // `probe.min_failures` threshold instead of being decayed away
        // by the much shorter generic `runtime_failure_window`. `0`
        // disables the dedicated counter; chunk-0 timeouts then only
        // feed the generic counter like any other failure.
        chunk0_failure_window: Duration::from_secs(
            lb.and_then(|l| l.chunk0_failure_window_secs).unwrap_or(300),
        ),
        global_udp_strict_health: lb.and_then(|l| l.global_udp_strict_health).unwrap_or(false),
        udp_ws_keepalive_interval: lb
            .and_then(|l| l.udp_ws_keepalive_secs)
            .map(Duration::from_secs)
            .or(Some(Duration::from_secs(60))),
        // Default: 60 s — WS Ping on idle VLESS-over-WS TCP sessions to keep
        // NAT/middleboxes warm.  SS-over-WS does not use this (mid-session
        // Pings break upstream SS framing); set to 0 to disable for VLESS too.
        tcp_ws_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_ws_keepalive_secs).unwrap_or(60);
            if secs == 0 {
                None
            } else {
                Some(Duration::from_secs(secs))
            }
        },
        // Default: 20 s — sends a WebSocket Ping on each idle warm-standby TCP
        // socket to keep connections alive through NAT/firewall idle-timeout
        // windows.  outline-ss-server handles WS Ping/Pong correctly.
        // Set to 0 to disable.
        tcp_ws_standby_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_ws_standby_keepalive_secs).unwrap_or(20);
            if secs == 0 {
                None
            } else {
                Some(Duration::from_secs(secs))
            }
        },
        // Default: 20 s — keeps active SOCKS TCP sessions alive through common
        // 25-30 s upstream idle-timeout windows (HAProxy, nginx, NAT tables).
        // Keepalives are SS2022 0-length encrypted chunks; SS1 uplinks ignore them.
        // They keep the path alive but do NOT reset `tcp_timeouts.socks_upstream_idle`;
        // only real payload bytes count as session activity. Set to 0 to disable.
        tcp_active_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_active_keepalive_secs).unwrap_or(20);
            if secs == 0 {
                None
            } else {
                Some(Duration::from_secs(secs))
            }
        },
        // Default: 20 s — short enough to comfortably beat typical NAT
        // (30 s) and HTTP keep-alive (15-60 s) idle timeouts, long enough
        // that the extra traffic on idle uplinks stays negligible. Set to
        // 0 to disable (cached probe pipes then rely solely on a fast
        // probe.interval to stay warm).
        warm_probe_keepalive_interval: {
            let secs = lb.and_then(|l| l.warm_probe_keepalive_secs).unwrap_or(20);
            if secs == 0 {
                None
            } else {
                Some(Duration::from_secs(secs))
            }
        },
        auto_failback: lb.and_then(|l| l.auto_failback).unwrap_or(false),
        // Default: 256 KiB — large enough to absorb typical HTTP
        // request bodies and idempotent RPC payloads, small enough
        // that holding it for N concurrent pinned sessions stays
        // negligible compared with kernel socket buffers. `0` disables
        // mid-session retry entirely (the ring is never allocated and
        // the orchestrator skips the redial step).
        tcp_mid_session_retry_buffer_bytes: lb
            .and_then(|l| l.tcp_mid_session_retry_buffer_bytes)
            .unwrap_or(256 * 1024),
        // Default: `1` — matches the original v1 behaviour. Most
        // retriable mid-session failures recover on the first
        // attempt; bumping the budget pays off only against
        // genuinely-flaky transports, and burns 256 KiB per attempt
        // (one full buffer replay) even on persistent failure.
        tcp_mid_session_retry_budget: lb.and_then(|l| l.tcp_mid_session_retry_budget).unwrap_or(1),
        // Default: `Soft` — matches the v1.1 behaviour (oversized
        // chunk goes through, session stays alive, future retries
        // surface `failed_replay`). `Hard` drops the session
        // immediately on the first oversized chunk to guarantee
        // retry-correctness for the rest.
        tcp_mid_session_retry_overflow_policy: lb
            .and_then(|l| l.tcp_mid_session_retry_overflow_policy)
            .unwrap_or(OverflowPolicy::Soft),
        // Default: 5 seconds — comfortably above any reasonable RTT,
        // short enough that a misbehaving server cannot stall the
        // pinned relay invisibly.
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(
            lb.and_then(|l| l.tcp_mid_session_retry_consume_timeout_secs)
                .unwrap_or(5),
        ),
        // Default: `true` — the v2 capability is gated at runtime on
        // (a) v1.x retry being enabled and (b) the server echoing v2,
        // so leaving this on is safe even against v1-only servers.
        // Operators can explicitly disable it to suppress the v2
        // advertise (e.g. while staging the server-side rollout).
        tcp_symmetric_replay_enabled: lb
            .and_then(|l| l.tcp_symmetric_replay_enabled)
            .unwrap_or(true),
        // Default: 1 MiB — a generous bound that lets servers using
        // any reasonable `downlink_buffer_bytes` (default 64 KiB,
        // realistic upper bound 4-8 MiB) replay freely while
        // protecting the client from a hostile peer that would
        // otherwise force unbounded buffering.
        tcp_symmetric_replay_max_bytes: lb
            .and_then(|l| l.tcp_symmetric_replay_max_bytes)
            .unwrap_or(1_048_576),
        // Default: `false` — TUN-side ICMP echo requests are always
        // answered locally, regardless of uplink health. Opting in turns
        // a ping through the TUN interface into a group-liveness signal:
        // replies stop while every uplink in the group is down.
        tun_suppress_icmp_reply_when_down: lb
            .and_then(|l| l.tun_suppress_icmp_reply_when_down)
            .unwrap_or(false),
        vless_udp_mux_limits: {
            let defaults = VlessUdpMuxLimits::default();
            VlessUdpMuxLimits {
                max_sessions: lb
                    .and_then(|l| l.vless_udp_max_sessions)
                    .unwrap_or(defaults.max_sessions),
                // `0` disables idle eviction (janitor task is not spawned).
                session_idle_timeout: match lb.and_then(|l| l.vless_udp_session_idle_secs) {
                    Some(0) => None,
                    Some(secs) => Some(Duration::from_secs(secs)),
                    None => defaults.session_idle_timeout,
                },
                janitor_interval: lb
                    .and_then(|l| l.vless_udp_janitor_interval_secs)
                    .map(Duration::from_secs)
                    .unwrap_or(defaults.janitor_interval),
            }
        },
    })
}
