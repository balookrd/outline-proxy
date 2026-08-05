use std::time::Duration;

use anyhow::{Result, bail};

use outline_uplink::{
    LoadBalancingConfig, LoadBalancingMode, OverflowPolicy, RoutingScope, VlessUdpMuxLimits,
};

use super::super::schema::LoadBalancingSection;
use super::uplinks::parse_human_duration;

pub(crate) fn load_balancing_config(
    lb: Option<&LoadBalancingSection>,
) -> Result<LoadBalancingConfig> {
    let rtt_ewma_alpha = lb.and_then(|l| l.rtt_ewma_alpha).unwrap_or(0.3);
    if !(rtt_ewma_alpha.is_finite() && 0.0 < rtt_ewma_alpha && rtt_ewma_alpha <= 1.0) {
        bail!("load_balancing.rtt_ewma_alpha must be in the range (0, 1]");
    }
    let loss_latency_penalty_k = lb.and_then(|l| l.loss_latency_penalty_k).unwrap_or(0.0);
    if !(loss_latency_penalty_k.is_finite() && loss_latency_penalty_k >= 0.0) {
        bail!("load_balancing.loss_latency_penalty_k must be a finite value >= 0");
    }
    let loss_latency_inflation_max = lb.and_then(|l| l.loss_latency_inflation_max).unwrap_or(4.0);
    // Upper-bounded, not just finite: an absurd cap (e.g. a typo like
    // `1e300`) lets `base_latency_with` saturate a wire's inflated latency
    // to `Duration::MAX`, which `weighted_latency_score` then feeds into the
    // panicking `Duration::from_secs_f64` in the selection hot path — for
    // any weight. 100x is far past any real-world path; reject anything
    // beyond it at load time instead of letting it panic dispatch later.
    if !(loss_latency_inflation_max.is_finite()
        && (1.0..=100.0).contains(&loss_latency_inflation_max))
    {
        bail!("load_balancing.loss_latency_inflation_max must be a finite value in [1, 100]");
    }
    let loss_ewma_alpha = lb.and_then(|l| l.loss_ewma_alpha).unwrap_or(0.2);
    if !(loss_ewma_alpha.is_finite() && 0.0 < loss_ewma_alpha && loss_ewma_alpha <= 1.0) {
        bail!("load_balancing.loss_ewma_alpha must be in the range (0, 1]");
    }
    // `0.0` is the documented off switch (see the field doc on
    // `LoadBalancingConfig::loss_failover_ratio`) — a value outside `[0, 1]`
    // is nonsense for a ratio and rejected here rather than silently
    // clamped, matching the sibling `loss_latency_penalty_k` /
    // `health_weight_floor` validations above.
    let loss_failover_ratio = lb.and_then(|l| l.loss_failover_ratio).unwrap_or(0.0);
    if !(loss_failover_ratio.is_finite() && (0.0..=1.0).contains(&loss_failover_ratio)) {
        bail!("load_balancing.loss_failover_ratio must be in the range [0, 1]");
    }
    let mode = lb.and_then(|l| l.mode).unwrap_or(LoadBalancingMode::ActiveActive);
    let routing_scope = lb.and_then(|l| l.routing_scope).unwrap_or(RoutingScope::PerFlow);
    let has_reselect_at = lb.and_then(|l| l.reselect_at.as_ref()).is_some_and(|v| !v.is_empty());
    let has_reselect_interval = lb.and_then(|l| l.reselect_interval.as_ref()).is_some();
    if has_reselect_at && has_reselect_interval {
        bail!(
            "load_balancing.reselect_at and load_balancing.reselect_interval are mutually \
             exclusive"
        );
    }
    if (has_reselect_at || has_reselect_interval)
        && (mode != LoadBalancingMode::ActivePassive
            || !matches!(routing_scope, RoutingScope::Global | RoutingScope::PerUplink))
    {
        bail!(
            "load_balancing.reselect_at / reselect_interval require mode = \"active_passive\" \
             and routing_scope = \"global\" or \"per_uplink\" (scheduled re-selection moves \
             the strict active slot, which only exists there)"
        );
    }
    Ok(LoadBalancingConfig {
        mode,
        routing_scope,
        shared_resume: lb.and_then(|l| l.shared_resume).unwrap_or(false),
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
        loss_latency_penalty_k,
        loss_latency_inflation_max,
        // Default: 10 s. `0` is the sampling loop's own off switch —
        // `UplinkManager::spawn_loss_sampler_loop` checks `interval.is_zero()`
        // and never spawns the loop at all, rather than spawning one that
        // busy-loops on a zero sleep. Documented (not rejected) because it is
        // a legitimate way to ship the carrier-loss probes (registration,
        // metrics wiring) without paying for the sampling timer, e.g. while
        // staging the feature.
        loss_sample_interval: Duration::from_secs(
            lb.and_then(|l| l.loss_sample_interval_secs).unwrap_or(10),
        ),
        loss_sample_min_packets: lb.and_then(|l| l.loss_sample_min_packets).unwrap_or(50),
        loss_ewma_alpha,
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
        // Default: 3 × mode_downgrade_secs — one isolated descent window
        // (a single flap installs exactly `mode_downgrade_secs` of cap)
        // can never cross the threshold; only a window continuously
        // re-extended by ongoing carrier failures does. `0` disables.
        carrier_degraded_failover: {
            let downgrade_secs = lb.and_then(|l| l.mode_downgrade_secs).unwrap_or(60);
            match lb.and_then(|l| l.carrier_degraded_failover_secs) {
                Some(0) => None,
                Some(secs) => Some(Duration::from_secs(secs)),
                None => Some(Duration::from_secs(downgrade_secs.saturating_mul(3))),
            }
        },
        loss_failover_ratio,
        // Unset or explicit `0` disables the check, exactly like
        // `carrier_degraded_failover_secs`'s `Some(0) => None` — no auto-
        // derived default here: unlike the carrier-descent window there is
        // no companion duration this could scale off, and inventing one
        // would silently turn the ratio knob live.
        loss_failover_duration: match lb.and_then(|l| l.loss_failover_secs) {
            Some(0) | None => None,
            Some(secs) => Some(Duration::from_secs(secs)),
        },
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
        // Default: `true` — rank wire / carrier-family selection by liveness
        // (see `LoadBalancingConfig::health_weighted_selection`). Set to
        // `false` to restore the legacy fixed cyclic order + binary cap.
        health_weighted_selection: lb.and_then(|l| l.health_weighted_selection).unwrap_or(true),
        health_weight_floor: {
            let floor = lb.and_then(|l| l.health_weight_floor).unwrap_or(0.05);
            if !(floor.is_finite() && (0.0..=1.0).contains(&floor)) {
                bail!("load_balancing.health_weight_floor must be in the range [0, 1]");
            }
            floor
        },
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
        // Unset derives the window from the probe schedule; an explicit `0`
        // keeps the legacy "health flag alone decides" behaviour.
        tun_icmp_liveness_window: lb
            .and_then(|l| l.tun_icmp_liveness_window_secs)
            .map(Duration::from_secs),
        // Default: `false` — a group with no healthy uplinks keeps traffic
        // parked on the group (legacy behaviour). Opting in turns a fully
        // down group into a live `direct` bypass until any uplink recovers.
        bypass_when_down: lb.and_then(|l| l.bypass_when_down).unwrap_or(false),
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
        reselect_at: {
            let mut slots = Vec::new();
            for entry in lb.and_then(|l| l.reselect_at.as_ref()).into_iter().flatten() {
                slots.push(parse_wall_clock(entry)?);
            }
            slots.sort_unstable();
            slots.dedup();
            slots
        },
        reselect_interval: lb
            .and_then(|l| l.reselect_interval.as_deref())
            .map(|s| parse_human_duration("reselect_interval", s))
            .transpose()?
            .map(|d| {
                if d < RESELECT_INTERVAL_MIN {
                    bail!(
                        "load_balancing.reselect_interval must be at least {}s: each firing \
                         moves the active uplink, and off a cluster (shared_resume = false) \
                         that tears down every in-flight SOCKS5 TCP session on this group",
                        RESELECT_INTERVAL_MIN.as_secs()
                    );
                }
                Ok(d)
            })
            .transpose()?,
    })
}

/// Floor for `reselect_interval`: below this, a firing every few seconds
/// would RST every in-flight SOCKS5 TCP session on a non-cluster group far
/// too often to be an operator-intended schedule rather than a typo (e.g.
/// bare `"10"` seconds instead of `"10h"`).
const RESELECT_INTERVAL_MIN: Duration = Duration::from_secs(60);

/// Parse a `"HH:MM"` local-time slot for `reselect_at`.
fn parse_wall_clock(input: &str) -> Result<(u8, u8)> {
    let parse = |part: &str, what: &str| -> Result<u8> {
        if part.is_empty() || part.len() > 2 || !part.chars().all(|c| c.is_ascii_digit()) {
            bail!("load_balancing.reselect_at entry \"{input}\": invalid {what}");
        }
        Ok(part.parse().expect("digits only, len <= 2"))
    };
    let Some((h, m)) = input.split_once(':') else {
        bail!("load_balancing.reselect_at entry \"{input}\" must be \"HH:MM\"");
    };
    let (hours, minutes) = (parse(h, "hours")?, parse(m, "minutes")?);
    if hours > 23 || minutes > 59 {
        bail!("load_balancing.reselect_at entry \"{input}\" out of range (00:00 - 23:59)");
    }
    Ok((hours, minutes))
}

#[cfg(test)]
#[path = "tests/balancing.rs"]
mod tests;
