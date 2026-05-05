use std::time::Duration;

use anyhow::{Result, bail};

use outline_uplink::{LoadBalancingConfig, LoadBalancingMode, RoutingScope, VlessUdpMuxLimits};

use super::super::schema::LoadBalancingSection;

pub(super) fn load_balancing_config(lb: Option<&LoadBalancingSection>) -> Result<LoadBalancingConfig> {
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
        global_udp_strict_health: lb
            .and_then(|l| l.global_udp_strict_health)
            .unwrap_or(false),
        udp_ws_keepalive_interval: lb
            .and_then(|l| l.udp_ws_keepalive_secs)
            .map(Duration::from_secs)
            .or(Some(Duration::from_secs(60))),
        // Default: 60 s — WS Ping on idle VLESS-over-WS TCP sessions to keep
        // NAT/middleboxes warm.  SS-over-WS does not use this (mid-session
        // Pings break upstream SS framing); set to 0 to disable for VLESS too.
        tcp_ws_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_ws_keepalive_secs).unwrap_or(60);
            if secs == 0 { None } else { Some(Duration::from_secs(secs)) }
        },
        // Default: 20 s — sends a WebSocket Ping on each idle warm-standby TCP
        // socket to keep connections alive through NAT/firewall idle-timeout
        // windows.  outline-ss-server handles WS Ping/Pong correctly.
        // Set to 0 to disable.
        tcp_ws_standby_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_ws_standby_keepalive_secs).unwrap_or(20);
            if secs == 0 { None } else { Some(Duration::from_secs(secs)) }
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
            let secs = lb
                .and_then(|l| l.warm_probe_keepalive_secs)
                .unwrap_or(20);
            if secs == 0 { None } else { Some(Duration::from_secs(secs)) }
        },
        auto_failback: lb.and_then(|l| l.auto_failback).unwrap_or(false),
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
