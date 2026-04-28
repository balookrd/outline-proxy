use tokio::time::Instant;

use super::super::config::{LoadBalancingMode, RoutingScope, UplinkTransport};
use super::super::penalty::current_penalty;
use super::super::selection::{effective_latency, selection_score};
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

fn routing_scope_name(scope: RoutingScope) -> &'static str {
    match scope {
        RoutingScope::PerFlow => "per_flow",
        RoutingScope::PerUplink => "per_uplink",
        RoutingScope::Global => "global",
    }
}

impl UplinkManager {
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
            uplinks.push(UplinkSnapshot {
                index,
                name: uplink.name.clone(),
                group: self.inner.group_name.clone(),
                transport: uplink.transport.to_string(),
                tcp_ws_mode: match uplink.transport {
                    UplinkTransport::Ws => {
                        uplink.tcp_ws_url.as_ref().map(|_| uplink.tcp_ws_mode.to_string())
                    },
                    UplinkTransport::Vless => {
                        uplink.vless_ws_url.as_ref().map(|_| uplink.vless_ws_mode.to_string())
                    },
                    UplinkTransport::Shadowsocks => None,
                },
                udp_ws_mode: match uplink.transport {
                    UplinkTransport::Ws => {
                        uplink.udp_ws_url.as_ref().map(|_| uplink.udp_ws_mode.to_string())
                    },
                    UplinkTransport::Vless => {
                        uplink.vless_ws_url.as_ref().map(|_| uplink.vless_ws_mode.to_string())
                    },
                    UplinkTransport::Shadowsocks => None,
                },
                weight: uplink.weight,
                tcp_healthy: status.tcp.healthy,
                udp_healthy: status.udp.healthy,
                tcp_latency_ms: status.tcp.latency.map(|v| v.as_millis()),
                udp_latency_ms: status.udp.latency.map(|v| v.as_millis()),
                tcp_rtt_ewma_ms: status.tcp.rtt_ewma.map(|v| v.as_millis()),
                udp_rtt_ewma_ms: status.udp.rtt_ewma.map(|v| v.as_millis()),
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
                    .h3_downgrade_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                h3_udp_downgrade_until_ms: status
                    .udp
                    .h3_downgrade_until
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                last_active_tcp_ago_ms: status
                    .tcp
                    .last_active
                    .map(|t| now.duration_since(t).as_millis()),
                last_active_udp_ago_ms: status
                    .udp
                    .last_active
                    .map(|t| now.duration_since(t).as_millis()),
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
