use std::time::Duration;

use anyhow::{Result, bail};

use outline_uplink::{LoadBalancingConfig, LoadBalancingMode, RoutingScope};

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
        h3_downgrade_duration: Duration::from_secs(
            lb.and_then(|l| l.h3_downgrade_secs).unwrap_or(60),
        ),
        udp_ws_keepalive_interval: lb
            .and_then(|l| l.udp_ws_keepalive_secs)
            .map(Duration::from_secs)
            .or(Some(Duration::from_secs(60))),
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
        // Set to 0 to disable.
        tcp_active_keepalive_interval: {
            let secs = lb.and_then(|l| l.tcp_active_keepalive_secs).unwrap_or(20);
            if secs == 0 {
                None
            } else {
                Some(Duration::from_secs(secs))
            }
        },
        auto_failback: lb.and_then(|l| l.auto_failback).unwrap_or(false),
    })
}
