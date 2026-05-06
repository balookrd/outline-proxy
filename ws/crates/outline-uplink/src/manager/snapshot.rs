use tokio::time::Instant;

use super::super::config::{LoadBalancingMode, RoutingScope, UplinkTransport};
use super::super::penalty::current_penalty;
use super::super::selection::{
    any_wire_recent_success, effective_health, effective_latency, selection_score,
};
use super::super::time::duration_to_millis_option;
use super::super::types::{
    StickyRouteSnapshot, TransportKind, UplinkManager, UplinkManagerSnapshot, UplinkSnapshot,
};

fn load_balancing_mode_name(mode: LoadBalancingMode) -> &'static str {
    match mode {
        LoadBalancingMode::ActiveActive => "active_active",
        LoadBalancingMode::ActivePassive => "active_passive",
    }
}

/// "Visualization truth" health: probe-confirmed health on this wire, or
/// — for uplinks with at least one fallback configured — `Some(true)`
/// when *any* wire has dialed successfully within the runtime-failure
/// window. Mirrors what `selection_health` consults for routing, so a
/// dashboard reading this field and a router making a candidate choice
/// agree on whether the uplink is delivering traffic.
///
/// Returns `None` when neither the probe verdict nor any-wire-success is
/// set yet (e.g. an instance that just started and hasn't completed its
/// first probe cycle).
fn compute_health_effective(
    status: &super::status::UplinkStatus,
    uplink: &super::super::types::Uplink,
    transport: TransportKind,
    now: Instant,
    config: &crate::config::LoadBalancingConfig,
) -> Option<bool> {
    if effective_health(status, transport, now) {
        return Some(true);
    }
    if any_wire_recent_success(status, uplink, transport, now, config) {
        return Some(true);
    }
    // Surface the negative probe verdict only when one exists; otherwise
    // leave the snapshot field empty so the consumer can distinguish "we
    // know this wire is down" from "we haven't probed it yet".
    status.of(transport).healthy.map(|_| false)
}

fn routing_scope_name(scope: RoutingScope) -> &'static str {
    match scope {
        RoutingScope::PerFlow => "per_flow",
        RoutingScope::PerUplink => "per_uplink",
        RoutingScope::Global => "global",
    }
}

/// Snapshot pair `(configured_submode, block_remaining_ms)` for the
/// XHTTP submode axis on a given dial direction. Returns `(None, None)`
/// when the uplink is not VLESS or has no dial URL — the submode
/// concept does not apply outside the XHTTP carriers, but VLESS uplinks
/// configured for `ws_*` carriers also fall through to `(None, None)`
/// because they never visit the XHTTP submode cache. The configured
/// half always reflects the URL exactly (including `packet-up` when no
/// `?mode=` is set), so dashboards can show the user's chosen shape
/// independent of the cache state.
/// Configured TCP mode string for a single wire entry. Mirrors
/// [`UplinkConfig::tcp_dial_mode`] but operates on a synthetic
/// transport+mode tuple drawn from primary or a fallback. Returns
/// `None` for Shadowsocks (no TransportMode enum applies).
fn wire_tcp_mode(transport: crate::config::UplinkTransport, ws_mode: crate::config::TransportMode, vless_mode: crate::config::TransportMode) -> Option<String> {
    use crate::config::UplinkTransport;
    match transport {
        UplinkTransport::Vless => Some(vless_mode.to_string()),
        UplinkTransport::Ws => Some(ws_mode.to_string()),
        UplinkTransport::Shadowsocks => None,
    }
}

/// XHTTP submode view for a per-wire dial URL. Returns
/// `(configured_submode, block_remaining_ms)`. Returns `(None, None)`
/// for non-VLESS / non-XHTTP wires — same semantics as
/// [`xhttp_submode_view`] but without the `transport` arg shadow check
/// because the caller already knows whether VLESS is the wire's
/// transport.
async fn wire_xhttp_submode(
    transport: crate::config::UplinkTransport,
    dial_url: Option<&url::Url>,
) -> (Option<String>, Option<u128>) {
    use crate::config::UplinkTransport;
    let Some(url) = dial_url else { return (None, None) };
    if !matches!(transport, UplinkTransport::Vless) {
        return (None, None);
    }
    let configured = outline_transport::XhttpSubmode::from_url(url).to_string();
    let remaining = outline_transport::xhttp_stream_one_block_remaining(url)
        .await
        .map(|d| d.as_millis());
    (Some(configured), remaining)
}

async fn xhttp_submode_view(
    dial_url: Option<&url::Url>,
    transport: UplinkTransport,
) -> (Option<String>, Option<u128>) {
    let Some(url) = dial_url else { return (None, None) };
    if !matches!(transport, UplinkTransport::Vless) {
        return (None, None);
    }
    let configured = outline_transport::XhttpSubmode::from_url(url).to_string();
    let remaining = outline_transport::xhttp_stream_one_block_remaining(url)
        .await
        .map(|d| d.as_millis());
    (Some(configured), remaining)
}

impl UplinkManager {
    /// Build the per-wire chain `[primary, fallbacks[0], ..., fallbacks[N-1]]`
    /// for snapshot export. Each entry surfaces:
    ///   * the transport family,
    ///   * configured TCP / UDP carrier mode strings,
    ///   * **effective** TCP / UDP modes after this wire's per-wire
    ///     mode-downgrade slot is applied,
    ///   * a `*_downgrade_active` boolean derived from
    ///     `effective != configured`,
    ///   * configured XHTTP submode + per-host stream-one block remaining
    ///     (only set on VLESS / XHTTP wires).
    ///
    /// Async because per-host stream-one block lookups go through
    /// `outline_transport::xhttp_stream_one_block_remaining`. Returns
    /// an empty Vec for single-wire uplinks — the existing top-level
    /// `tcp_mode` / `udp_mode` / `tcp_xhttp_submode*` fields already
    /// carry primary's state in that case.
    async fn build_wire_chain_async(
        &self,
        index: usize,
        uplink: &super::super::types::Uplink,
    ) -> Vec<outline_metrics::WireSnapshot> {
        use crate::config::UplinkTransport;
        use outline_metrics::WireSnapshot;
        if uplink.fallbacks.is_empty() {
            return Vec::new();
        }
        let mut chain = Vec::with_capacity(1 + uplink.fallbacks.len());
        // Primary wire (index 0) inherits its mode from the parent
        // `UplinkConfig`. Effective mode comes from the existing
        // `effective_*_mode_for_wire(0)` path which folds in primary's
        // top-level mode-downgrade slot.
        let primary_tcp_configured = wire_tcp_mode(uplink.transport, uplink.tcp_mode, uplink.vless_mode);
        let primary_udp_configured = wire_tcp_mode(uplink.transport, uplink.udp_mode, uplink.vless_mode);
        let primary_tcp_eff = self.effective_tcp_mode_for_wire(index, 0).await.to_string();
        let primary_udp_eff = self.effective_udp_mode_for_wire(index, 0).await.to_string();
        let (primary_tcp_sm, primary_tcp_block) =
            wire_xhttp_submode(uplink.transport, uplink.tcp_dial_url()).await;
        let (primary_udp_sm, primary_udp_block) =
            wire_xhttp_submode(uplink.transport, uplink.udp_dial_url()).await;
        let (primary_tcp_eff_opt, primary_tcp_dg) = match uplink.transport {
            UplinkTransport::Shadowsocks => (None, false),
            _ => (Some(primary_tcp_eff.clone()), primary_tcp_configured.as_deref() != Some(&primary_tcp_eff)),
        };
        let (primary_udp_eff_opt, primary_udp_dg) = match uplink.transport {
            UplinkTransport::Shadowsocks => (None, false),
            _ => (Some(primary_udp_eff.clone()), primary_udp_configured.as_deref() != Some(&primary_udp_eff)),
        };
        chain.push(WireSnapshot {
            transport: uplink.transport.to_string(),
            tcp_downgrade_active: primary_tcp_dg,
            udp_downgrade_active: primary_udp_dg,
            tcp_mode: primary_tcp_configured,
            udp_mode: primary_udp_configured,
            tcp_mode_effective: primary_tcp_eff_opt,
            udp_mode_effective: primary_udp_eff_opt,
            tcp_xhttp_submode: primary_tcp_sm,
            tcp_xhttp_submode_block_remaining_ms: primary_tcp_block,
            udp_xhttp_submode: primary_udp_sm,
            udp_xhttp_submode_block_remaining_ms: primary_udp_block,
        });
        for (offset, fb) in uplink.fallbacks.iter().enumerate() {
            let wire_idx = (offset + 1) as u8;
            let configured_tcp = wire_tcp_mode(fb.transport, fb.tcp_mode, fb.vless_mode);
            let configured_udp = wire_tcp_mode(fb.transport, fb.udp_mode, fb.vless_mode);
            let eff_tcp = self.effective_tcp_mode_for_wire(index, wire_idx).await.to_string();
            let eff_udp = self.effective_udp_mode_for_wire(index, wire_idx).await.to_string();
            let (sm_tcp, block_tcp) = wire_xhttp_submode(fb.transport, fb.tcp_dial_url()).await;
            let (sm_udp, block_udp) = wire_xhttp_submode(fb.transport, fb.udp_dial_url()).await;
            let (eff_tcp_opt, dg_tcp) = match fb.transport {
                UplinkTransport::Shadowsocks => (None, false),
                _ => (Some(eff_tcp.clone()), configured_tcp.as_deref() != Some(&eff_tcp)),
            };
            let (eff_udp_opt, dg_udp) = match fb.transport {
                UplinkTransport::Shadowsocks => (None, false),
                _ => (Some(eff_udp.clone()), configured_udp.as_deref() != Some(&eff_udp)),
            };
            chain.push(WireSnapshot {
                transport: fb.transport.to_string(),
                tcp_downgrade_active: dg_tcp,
                udp_downgrade_active: dg_udp,
                tcp_mode: configured_tcp,
                udp_mode: configured_udp,
                tcp_mode_effective: eff_tcp_opt,
                udp_mode_effective: eff_udp_opt,
                tcp_xhttp_submode: sm_tcp,
                tcp_xhttp_submode_block_remaining_ms: block_tcp,
                udp_xhttp_submode: sm_udp,
                udp_xhttp_submode_block_remaining_ms: block_udp,
            });
        }
        chain
    }

    pub async fn snapshot(&self) -> UplinkManagerSnapshot {
        let now = Instant::now();
        let statuses = self.inner.snapshot_statuses();
        let active = self.inner.active_uplinks.read().await;
        let global_active_index = active.global;
        let global_active_reason = active.global_reason.clone();
        let tcp_active_index = active.tcp;
        let tcp_active_reason = active.tcp_reason.clone();
        let udp_active_index = active.udp;
        let udp_active_reason = active.udp_reason.clone();
        drop(active);

        let mut uplinks = Vec::with_capacity(self.inner.uplinks.len());
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            let status = &statuses[index];
            let standby_tcp_ready = self.inner.standby_pools[index].tcp.len_hint();
            let standby_udp_ready = self.inner.standby_pools[index].udp.len_hint();
            let tcp_penalty = current_penalty(&status.tcp.penalty, now, &self.inner.load_balancing);
            let udp_penalty = current_penalty(&status.udp.penalty, now, &self.inner.load_balancing);
            let tcp_effective_latency =
                effective_latency(status, TransportKind::Tcp, now, &self.inner.load_balancing);
            let udp_effective_latency =
                effective_latency(status, TransportKind::Udp, now, &self.inner.load_balancing);
            let tcp_score = selection_score(
                status,
                uplink.weight,
                TransportKind::Tcp,
                now,
                &self.inner.load_balancing,
                self.inner.load_balancing.routing_scope,
            );
            let udp_score = selection_score(
                status,
                uplink.weight,
                TransportKind::Udp,
                now,
                &self.inner.load_balancing,
                self.inner.load_balancing.routing_scope,
            );
            // XHTTP submode visibility: configured shape comes from the
            // `?mode=` query on the dial URL; the per-host stream-one
            // block lives in the transport-crate cache. We expose both
            // halves so the dashboard can render the configured carrier
            // and signal when a stream-one URL is being silently served
            // by packet-up because of a recent failure.
            let (tcp_xhttp_submode, tcp_xhttp_submode_block_remaining_ms) =
                xhttp_submode_view(uplink.tcp_dial_url(), uplink.transport).await;
            let (udp_xhttp_submode, udp_xhttp_submode_block_remaining_ms) =
                xhttp_submode_view(uplink.udp_dial_url(), uplink.transport).await;
            uplinks.push(UplinkSnapshot {
                index,
                name: uplink.name.clone(),
                group: self.inner.group_name.clone(),
                transport: uplink.transport.to_string(),
                tcp_mode: match uplink.transport {
                    UplinkTransport::Ws => {
                        uplink.tcp_ws_url.as_ref().map(|_| uplink.tcp_mode.to_string())
                    },
                    UplinkTransport::Vless => uplink
                        .tcp_dial_url()
                        .map(|_| uplink.vless_mode.to_string()),
                    UplinkTransport::Shadowsocks => None,
                },
                udp_mode: match uplink.transport {
                    UplinkTransport::Ws => {
                        uplink.udp_ws_url.as_ref().map(|_| uplink.udp_mode.to_string())
                    },
                    UplinkTransport::Vless => uplink
                        .udp_dial_url()
                        .map(|_| uplink.vless_mode.to_string()),
                    UplinkTransport::Shadowsocks => None,
                },
                weight: uplink.weight,
                tcp_healthy: status.tcp.healthy,
                udp_healthy: status.udp.healthy,
                tcp_health_effective: compute_health_effective(
                    status,
                    uplink,
                    TransportKind::Tcp,
                    now,
                    &self.inner.load_balancing,
                ),
                udp_health_effective: compute_health_effective(
                    status,
                    uplink,
                    TransportKind::Udp,
                    now,
                    &self.inner.load_balancing,
                ),
                tcp_latency_ms: status.tcp.latency.map(|v| v.as_millis()),
                udp_latency_ms: status.udp.latency.map(|v| v.as_millis()),
                tcp_rtt_ewma_ms: status.tcp.rtt_ewma.map(|v| v.as_millis()),
                udp_rtt_ewma_ms: status.udp.rtt_ewma.map(|v| v.as_millis()),
                tcp_active_wire_rtt_ewma_ms: status
                    .tcp
                    .active_wire_rtt_ewma()
                    .map(|v| v.as_millis()),
                udp_active_wire_rtt_ewma_ms: status
                    .udp
                    .active_wire_rtt_ewma()
                    .map(|v| v.as_millis()),
                tcp_penalty_ms: duration_to_millis_option(tcp_penalty),
                udp_penalty_ms: duration_to_millis_option(udp_penalty),
                tcp_effective_latency_ms: duration_to_millis_option(tcp_effective_latency),
                udp_effective_latency_ms: duration_to_millis_option(udp_effective_latency),
                tcp_score_ms: duration_to_millis_option(tcp_score),
                udp_score_ms: duration_to_millis_option(udp_score),
                cooldown_tcp_ms: status
                    .tcp
                    .cooldown_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                cooldown_udp_ms: status
                    .udp
                    .cooldown_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                last_checked_ago_ms: status
                    .last_checked
                    .map(|checked| now.duration_since(checked).as_millis()),
                last_error: status.last_error.clone(),
                standby_tcp_ready,
                standby_udp_ready,
                tcp_consecutive_failures: status.tcp.consecutive_failures,
                udp_consecutive_failures: status.udp.consecutive_failures,
                h3_tcp_downgrade_until_ms: status
                    .tcp
                    .mode_downgrade_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                h3_udp_downgrade_until_ms: status
                    .udp
                    .mode_downgrade_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                tcp_mode_capped_to: status
                    .tcp
                    .mode_downgrade_capped_to
                    .map(|m| m.to_string()),
                udp_mode_capped_to: status
                    .udp
                    .mode_downgrade_capped_to
                    .map(|m| m.to_string()),
                tcp_xhttp_submode,
                udp_xhttp_submode,
                tcp_xhttp_submode_block_remaining_ms,
                udp_xhttp_submode_block_remaining_ms,
                last_active_tcp_ago_ms: status
                    .tcp
                    .last_active
                    .map(|t| now.duration_since(t).as_millis()),
                last_active_udp_ago_ms: status
                    .udp
                    .last_active
                    .map(|t| now.duration_since(t).as_millis()),
                configured_fallbacks: uplink
                    .fallbacks
                    .iter()
                    .map(|fb| fb.transport.to_string())
                    .collect(),
                configured_wire_chain: self
                    .build_wire_chain_async(index, uplink)
                    .await,
                tcp_active_wire: status.tcp.active_wire,
                udp_active_wire: status.udp.active_wire,
                tcp_active_wire_pin_remaining_ms: status
                    .tcp
                    .active_wire_pinned_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                udp_active_wire_pin_remaining_ms: status
                    .udp
                    .active_wire_pinned_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
            });
        }

        let global_active_uplink = global_active_index
            .and_then(|index| self.inner.uplinks.get(index))
            .map(|uplink| uplink.name.clone());
        let per_uplink = self.strict_per_uplink_active_uplink();
        let tcp_active_uplink = per_uplink
            .then(|| {
                tcp_active_index
                    .and_then(|i| self.inner.uplinks.get(i))
                    .map(|u| u.name.clone())
            })
            .flatten();
        let udp_active_uplink = per_uplink
            .then(|| {
                udp_active_index
                    .and_then(|i| self.inner.uplinks.get(i))
                    .map(|u| u.name.clone())
            })
            .flatten();

        let sticky_routes = {
            let sticky = self.inner.sticky_routes.read().await;
            sticky
                .iter()
                .filter_map(|(key, route)| {
                    route.expires_at.checked_duration_since(now).map(|remaining| {
                        StickyRouteSnapshot {
                            key: key.to_string(),
                            uplink_index: route.uplink_index,
                            uplink_name: self.inner.uplinks[route.uplink_index].name.clone(),
                            expires_in_ms: remaining.as_millis(),
                        }
                    })
                })
                .collect()
        };

        UplinkManagerSnapshot {
            group: self.inner.group_name.clone(),
            generated_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            load_balancing_mode: load_balancing_mode_name(self.inner.load_balancing.mode)
                .to_string(),
            routing_scope: routing_scope_name(self.inner.load_balancing.routing_scope).to_string(),
            auto_failback: self.inner.load_balancing.auto_failback,
            global_active_uplink,
            global_active_reason,
            tcp_active_uplink,
            tcp_active_reason,
            udp_active_uplink,
            udp_active_reason,
            uplinks,
            sticky_routes,
        }
    }
}
