#[cfg(test)]
#[path = "tests/snapshot.rs"]
mod tests;

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::time::Duration;

use tokio::time::Instant;

use super::super::config::{LoadBalancingMode, RoutingScope, UplinkTransport};
use super::super::penalty::current_penalty;
use super::super::routing_key::RoutingKey;
use super::super::selection::{
    any_wire_recent_success, effective_health, effective_latency, selection_score,
};
use super::super::time::duration_to_millis_option;
use super::super::types::{
    StickyRouteSnapshot, TransportKind, UplinkManager, UplinkManagerSnapshot, UplinkSnapshot,
};

/// How many sticky-route entries a snapshot serialises. The map itself is
/// bounded by `MAX_STICKY_ROUTES` (100k per group) and a snapshot is rebuilt on
/// every Prometheus scrape and dashboard poll, so serialising all of it burned
/// a `String` per entry per scrape on a surface nobody reads past the first
/// screen. The entries are a sample for eyeballing; the accounting surface is
/// `sticky_routes_total` / `sticky_routes_by_uplink`, which stay exact.
pub(crate) const STICKY_ROUTES_SNAPSHOT_LIMIT: usize = 1000;

/// Borrowed sticky-route entry ranked by remaining TTL. Lets the sampler keep
/// the longest-lived pins in a bounded min-heap — one pass over the map, and
/// only the survivors get stringified. Ordering is on `remaining` alone: ties
/// are interchangeable for sampling, so `Eq` here means "ranks the same", not
/// "same entry".
struct RankedStickyRoute<'a> {
    remaining: Duration,
    key: &'a RoutingKey,
    uplink_index: usize,
}

impl Ord for RankedStickyRoute<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.remaining.cmp(&other.remaining)
    }
}

impl PartialOrd for RankedStickyRoute<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for RankedStickyRoute<'_> {}

impl PartialEq for RankedStickyRoute<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.remaining == other.remaining
    }
}

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
/// Returns `None` only when the uplink genuinely has no verdict to report:
/// a freshly started instance that has not completed its first probe cycle,
/// or a single-wire uplink whose probe has not rendered a verdict yet — so
/// the consumer can still tell "down" from "not yet probed". A multi-wire
/// uplink that HAS been probed but has no live wire reports `Some(false)`
/// even while the `shuffle_wires` round-gate holds `status.healthy` at `None`
/// (a dead chain rotating), so a fully-dead uplink is not rendered as a live
/// "Ready" row.
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
    // No positive signal. An explicit probe verdict is reported as-is (the
    // `Some(true)` case was already caught by `effective_health`, so a present
    // verdict here is a negative one).
    if status.of(transport).healthy.is_some() {
        return Some(false);
    }
    // `healthy == None`: no probe verdict has flipped the uplink. For a
    // multi-wire uplink that has already been probed (`last_checked` set) but
    // where neither the primary probe nor any fallback wire is currently alive
    // (both checks above failed), the round-gate is merely holding the
    // uplink-level flip back while a dead chain rotates — surface it as down
    // so a fully-dead uplink is not painted "Ready". Probe state survives the
    // anti-DPI reroll, so this verdict is stable. A never-probed or single-wire
    // uplink stays `None` (genuinely unknown).
    if status.last_checked.is_some() && !uplink.fallbacks.is_empty() {
        return Some(false);
    }
    None
}

fn routing_scope_name(scope: RoutingScope) -> &'static str {
    match scope {
        RoutingScope::PerFlow => "per_flow",
        RoutingScope::PerUplink => "per_uplink",
        RoutingScope::PerClient => "per_client",
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
/// transport+mode tuple drawn from primary or a fallback.
fn wire_tcp_mode(
    transport: crate::config::UplinkTransport,
    ws_mode: crate::config::TransportMode,
    vless_mode: crate::config::TransportMode,
) -> Option<String> {
    use crate::config::UplinkTransport;
    match transport {
        UplinkTransport::Vless => Some(vless_mode.to_string()),
        UplinkTransport::Ss => Some(ws_mode.to_string()),
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
    let configured = outline_transport::submode_from_url(url).to_string();
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
    let configured = outline_transport::submode_from_url(url).to_string();
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
        use outline_metrics::WireSnapshot;
        if uplink.fallbacks.is_empty() {
            return Vec::new();
        }
        let mut chain = Vec::with_capacity(1 + uplink.fallbacks.len());
        // Primary wire (index 0) inherits its mode from the parent
        // `UplinkConfig`. Effective mode comes from the existing
        // `effective_*_mode_for_wire(0)` path which folds in primary's
        // top-level mode-downgrade slot.
        // `*_dial_mode()` is combined-SS-aware (returns `ss_mode` for a
        // combined wire); reading the raw `tcp_mode`/`udp_mode` here showed the
        // split default for combined wires, which also made `configured !=
        // effective` and lit a phantom downgrade flag on the dashboard.
        let primary_tcp_configured =
            wire_tcp_mode(uplink.transport, uplink.tcp_dial_mode(), uplink.vless_mode);
        let primary_udp_configured =
            wire_tcp_mode(uplink.transport, uplink.udp_dial_mode(), uplink.vless_mode);
        let primary_tcp_eff = self.effective_tcp_mode_for_wire(index, 0).await.to_string();
        let primary_udp_eff = self.effective_udp_mode_for_wire(index, 0).await.to_string();
        let (primary_tcp_sm, primary_tcp_block) =
            wire_xhttp_submode(uplink.transport, uplink.tcp_dial_url()).await;
        let (primary_udp_sm, primary_udp_block) =
            wire_xhttp_submode(uplink.transport, uplink.udp_dial_url()).await;
        let primary_tcp_eff_opt = Some(primary_tcp_eff.clone());
        let primary_tcp_dg = primary_tcp_configured.as_deref() != Some(&primary_tcp_eff);
        let primary_udp_eff_opt = Some(primary_udp_eff.clone());
        let primary_udp_dg = primary_udp_configured.as_deref() != Some(&primary_udp_eff);
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
            let configured_tcp = wire_tcp_mode(fb.transport, fb.tcp_dial_mode(), fb.vless_mode);
            let configured_udp = wire_tcp_mode(fb.transport, fb.udp_dial_mode(), fb.vless_mode);
            let eff_tcp = self.effective_tcp_mode_for_wire(index, wire_idx).await.to_string();
            let eff_udp = self.effective_udp_mode_for_wire(index, wire_idx).await.to_string();
            let (sm_tcp, block_tcp) = wire_xhttp_submode(fb.transport, fb.tcp_dial_url()).await;
            let (sm_udp, block_udp) = wire_xhttp_submode(fb.transport, fb.udp_dial_url()).await;
            let eff_tcp_opt = Some(eff_tcp.clone());
            let dg_tcp = configured_tcp.as_deref() != Some(&eff_tcp);
            let eff_udp_opt = Some(eff_udp.clone());
            let dg_udp = configured_udp.as_deref() != Some(&eff_udp);
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
                    UplinkTransport::Ss => {
                        uplink.tcp_dial_url().map(|_| uplink.tcp_dial_mode().to_string())
                    },
                    UplinkTransport::Vless => {
                        uplink.tcp_dial_url().map(|_| uplink.vless_mode.to_string())
                    },
                },
                udp_mode: match uplink.transport {
                    UplinkTransport::Ss => {
                        uplink.udp_dial_url().map(|_| uplink.udp_dial_mode().to_string())
                    },
                    UplinkTransport::Vless => {
                        uplink.udp_dial_url().map(|_| uplink.vless_mode.to_string())
                    },
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
                cert_not_after_unix_ms: status.cert_not_after_unix_ms,
                standby_tcp_ready,
                standby_udp_ready,
                tcp_consecutive_failures: status.tcp.consecutive_failures,
                udp_consecutive_failures: status.udp.consecutive_failures,
                tcp_downstream_throttle_count: status.tcp.downstream_throttle_count,
                udp_downstream_throttle_count: status.udp.downstream_throttle_count,
                tcp_throttle_ago_ms: status
                    .tcp
                    .last_downstream_throttle_at
                    .map(|at| now.duration_since(at).as_millis()),
                udp_throttle_ago_ms: status
                    .udp
                    .last_downstream_throttle_at
                    .map(|at| now.duration_since(at).as_millis()),
                h3_tcp_downgrade_until_ms: status
                    .tcp
                    .descent
                    .until()
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                h3_udp_downgrade_until_ms: status
                    .udp
                    .descent
                    .until()
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                tcp_mode_capped_to: status.tcp.descent.capped_to().map(|m| m.to_string()),
                udp_mode_capped_to: status.udp.descent.capped_to().map(|m| m.to_string()),
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
                configured_wire_chain: self.build_wire_chain_async(index, uplink).await,
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
                // Per-uplink shuffle_wires settings + per-transport round
                // counters. The dashboard pairs `shuffle_wires` with the
                // counter and `*_active_wire` to highlight which wires of
                // the chain are already tried-and-failed in the current
                // round (preceding the active one in forward order).
                shuffle_wires: uplink.shuffle_wires,
                tcp_wires_failed_in_round: status.tcp.wires_failed_in_round,
                udp_wires_failed_in_round: status.udp.wires_failed_in_round,
                carrier_downgrade: uplink.carrier_downgrade,
                padding_override: uplink.padding,
                shuffle_timer_secs: uplink.shuffle_timer.map(|d| d.as_secs()),
                // Effective strategy: per-uplink override wins, otherwise
                // the process-wide default wired by `init_strategy`. The
                // task-local `with_strategy_override` scope is irrelevant
                // here — the snapshot path runs outside it, so reading
                // the global is the right baseline for "what would a
                // fresh dial under this uplink see".
                fingerprint_profile_strategy: {
                    let strategy = uplink
                        .fingerprint_profile
                        .unwrap_or_else(outline_transport::current_fingerprint_profile_strategy);
                    strategy.as_str().to_string()
                },
                // Active profile name for the primary dial URL under the
                // effective strategy. We look up the profile *here* (not
                // in the renderer) so the snapshot reflects the current
                // OnceLock-frozen pool rather than letting the dashboard
                // re-do the hash. `tcp_dial_url` covers WS / VLESS / XHTTP;
                // `udp_dial_url` is the fallback for UDP-only uplinks.
                // A wire without a dial URL returns `None` — the
                // fingerprint module's HTTP-header surface doesn't apply
                // without an HTTP carrier, so showing a profile would be a lie.
                fingerprint_profile_name: {
                    let strategy = uplink
                        .fingerprint_profile
                        .unwrap_or_else(outline_transport::current_fingerprint_profile_strategy);
                    use outline_transport::FingerprintProfileStrategy;
                    match strategy {
                        FingerprintProfileStrategy::None => None,
                        // `Random` rotates per dial — there is no "the"
                        // active profile a snapshot can pin. Surface
                        // the strategy token so the dashboard chip
                        // still renders something meaningful instead
                        // of going dark.
                        FingerprintProfileStrategy::Random => Some("random".to_string()),
                        // PerHostStable / ProcessStable: both resolve
                        // to a deterministic pool entry once `select_with_strategy`
                        // sees a URL. PerHostStable hashes by host:port,
                        // ProcessStable returns the process-wide pick
                        // and ignores the URL — but we still gate on
                        // "uplink has a URL" because Shadowsocks-over-
                        // raw-socket has no HTTP-headers surface, so
                        // claiming a profile applied there would be a
                        // lie on the dashboard.
                        FingerprintProfileStrategy::PerHostStable
                        | FingerprintProfileStrategy::ProcessStable => uplink
                            .tcp_dial_url()
                            .or_else(|| uplink.udp_dial_url())
                            .and_then(|url| {
                                outline_transport::fingerprint_profile::select_with_strategy(
                                    url, strategy,
                                )
                                .map(|p| p.name.to_string())
                            }),
                    }
                },
                admin_disabled: !self.inner.admin_enabled(index),
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

        // One pass over the sticky map: exact counts for the metrics surface,
        // plus a bounded longest-TTL-first sample for the dashboard. Only the
        // sampled entries allocate.
        let (sticky_routes, sticky_routes_total, sticky_routes_by_uplink) = {
            let sticky = self.inner.sticky_routes.read().await;
            let mut total = 0usize;
            let mut by_uplink = vec![0usize; self.inner.uplinks.len()];
            let mut sample: BinaryHeap<Reverse<RankedStickyRoute<'_>>> =
                BinaryHeap::with_capacity(STICKY_ROUTES_SNAPSHOT_LIMIT.min(sticky.len()));
            for (key, route) in sticky.iter() {
                let Some(remaining) = route.expires_at.checked_duration_since(now) else {
                    continue;
                };
                total += 1;
                if let Some(count) = by_uplink.get_mut(route.uplink_index) {
                    *count += 1;
                }
                let ranked = RankedStickyRoute {
                    remaining,
                    key,
                    uplink_index: route.uplink_index,
                };
                if sample.len() < STICKY_ROUTES_SNAPSHOT_LIMIT {
                    sample.push(Reverse(ranked));
                } else if let Some(Reverse(shortest)) = sample.peek()
                    && ranked.remaining > shortest.remaining
                {
                    sample.pop();
                    sample.push(Reverse(ranked));
                }
            }
            // `into_sorted_vec` on a `Reverse` min-heap yields descending
            // remaining TTL — freshest pins first.
            let entries = sample
                .into_sorted_vec()
                .into_iter()
                .map(|Reverse(ranked)| StickyRouteSnapshot {
                    key: ranked.key.to_string(),
                    uplink_index: ranked.uplink_index,
                    uplink_name: self.inner.uplinks[ranked.uplink_index].name.clone(),
                    expires_in_ms: ranked.remaining.as_millis(),
                })
                .collect();
            (entries, total, by_uplink)
        };

        // Live bypass state: mirrors the dispatch-layer decision
        // (`group_bypasses_when_down`) — the flag is config, the per-transport
        // active bits consult the same `has_any_healthy` signal routing uses,
        // so the dashboard / metrics and the router always agree on whether
        // traffic is currently escaping direct. The health walk only runs for
        // opted-in groups.
        let bypass_when_down = self.inner.load_balancing.bypass_when_down;
        let bypass_active_tcp = bypass_when_down && !self.has_any_healthy(TransportKind::Tcp).await;
        let bypass_active_udp = bypass_when_down && !self.has_any_healthy(TransportKind::Udp).await;

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
            shared_resume: self.inner.load_balancing.shared_resume,
            bypass_when_down,
            bypass_active_tcp,
            bypass_active_udp,
            global_active_uplink,
            global_active_reason,
            tcp_active_uplink,
            tcp_active_reason,
            udp_active_uplink,
            udp_active_reason,
            uplinks,
            sticky_routes,
            sticky_routes_total,
            sticky_routes_by_uplink,
        }
    }
}
