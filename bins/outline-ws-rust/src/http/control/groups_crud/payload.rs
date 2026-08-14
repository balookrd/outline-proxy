//! Wire types + TOML conversion for `/control/uplink_groups`.
//!
//! A `[[uplink_group]]` is addressed by its `name` (identity), like
//! `uplinks_crud` addresses `[[outline.uplinks]]` — so, unlike index-addressed
//! `routes_crud`, there is no `revision` guard: a named lookup is stable across
//! concurrent edits (last-write-wins on the same group, the same trade-off the
//! uplink editor already ships).
//!
//! Group policy has ~52 fields. Rather than a hand-written field-by-field
//! `payload_to_table`, the payload round-trips through `toml::to_string` (which
//! omits `None` fields) → `DocumentMut`. `mode`/`routing_scope`/
//! `tcp_mid_session_retry_overflow_policy` are carried as raw strings (parsed
//! into their enums only when the rendered TOML is re-parsed as
//! `UplinkGroupSection`); `probe` is an opaque `toml::Value` sub-table whose own
//! `deny_unknown_fields` is enforced at that same re-parse. `deny_unknown_fields`
//! here makes a mistyped top-level key a 400, not a silently-dropped setting.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::{DocumentMut, Table};

use crate::config::UplinkGroupSection;
use crate::http::control::config_edit::render_table_with_arrays;
// Re-exported so `list.rs` can reach it as `super::payload::table_to_json`.
pub(super) use crate::http::control::config_edit::table_to_json;

/// Mirrors `crate::config::UplinkGroupSection`; every field optional. `toml`
/// omits `None` on serialize, so no per-field `skip_serializing_if` is needed.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GroupPayload {
    pub(super) name: Option<String>,
    pub(super) mode: Option<String>,
    pub(super) routing_scope: Option<String>,
    pub(super) shared_resume: Option<bool>,
    pub(super) sticky_ttl_secs: Option<u64>,
    pub(super) hysteresis_ms: Option<u64>,
    pub(super) failure_cooldown_secs: Option<u64>,
    pub(super) tcp_chunk0_failover_timeout_secs: Option<u64>,
    pub(super) warm_standby_tcp: Option<usize>,
    pub(super) warm_standby_udp: Option<usize>,
    pub(super) rtt_ewma_alpha: Option<f64>,
    pub(super) rtt_ewma_halflife_secs: Option<u64>,
    pub(super) loss_latency_penalty_k: Option<f64>,
    pub(super) loss_latency_inflation_max: Option<f64>,
    pub(super) loss_sample_interval_secs: Option<u64>,
    pub(super) loss_sample_min_packets: Option<u64>,
    pub(super) loss_ewma_alpha: Option<f64>,
    pub(super) failure_penalty_ms: Option<u64>,
    pub(super) failure_penalty_max_ms: Option<u64>,
    pub(super) failure_penalty_halflife_secs: Option<u64>,
    pub(super) mode_downgrade_secs: Option<u64>,
    pub(super) carrier_degraded_failover_secs: Option<u64>,
    pub(super) loss_failover_ratio: Option<f64>,
    pub(super) loss_failover_secs: Option<u64>,
    pub(super) runtime_failure_window_secs: Option<u64>,
    pub(super) chunk0_failure_window_secs: Option<u64>,
    pub(super) global_udp_strict_health: Option<bool>,
    pub(super) udp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_standby_keepalive_secs: Option<u64>,
    pub(super) tcp_active_keepalive_secs: Option<u64>,
    pub(super) warm_probe_keepalive_secs: Option<u64>,
    pub(super) auto_failback: Option<bool>,
    pub(super) health_weighted_selection: Option<bool>,
    pub(super) tun_wire_dial: Option<bool>,
    pub(super) health_weight_floor: Option<f64>,
    pub(super) vless_udp_max_sessions: Option<usize>,
    pub(super) vless_udp_session_idle_secs: Option<u64>,
    pub(super) vless_udp_janitor_interval_secs: Option<u64>,
    pub(super) tcp_mid_session_retry_buffer_bytes: Option<usize>,
    pub(super) tcp_mid_session_retry_budget: Option<u8>,
    pub(super) tcp_mid_session_retry_overflow_policy: Option<String>,
    pub(super) tcp_mid_session_retry_consume_timeout_secs: Option<u64>,
    pub(super) tcp_symmetric_replay_enabled: Option<bool>,
    pub(super) tcp_symmetric_replay_max_bytes: Option<usize>,
    pub(super) tun_suppress_icmp_reply_when_down: Option<bool>,
    pub(super) tun_icmp_liveness_window_secs: Option<u64>,
    pub(super) bypass_when_down: Option<bool>,
    pub(super) reselect_at: Option<Vec<String>>,
    pub(super) reselect_interval: Option<String>,
    pub(super) reselect_sync: Option<bool>,
    /// Opaque probe-override sub-table (validated as `ProbeSection` when the
    /// rendered TOML is re-parsed). Kept last so `toml::to_string` emits every
    /// scalar/array field before this `[probe]` table (TOML requires it).
    pub(super) probe: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateBody {
    pub(super) group: GroupPayload,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpdateBody {
    pub(super) name: String,
    pub(super) patch: GroupPayload,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteBody {
    pub(super) name: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReorderBody {
    pub(super) name: String,
    /// Target position of `name` among all groups (0-based, declaration order).
    /// Out-of-range is rejected. Group order is cosmetic (selection is by the
    /// routing `via` rule, not position), so this only rewrites on-disk order.
    pub(super) to: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct MutationResponse {
    pub(super) name: String,
    pub(super) action: &'static str,
    /// Whether clients should call `/control/apply` to activate this staged
    /// config-file change without restarting the process.
    pub(super) apply_required: bool,
    /// Back-compat activation hint for control states that cannot hot-apply.
    pub(super) restart_required: bool,
}

impl MutationResponse {
    pub(super) fn staged(name: String, action: &'static str, hot_apply_available: bool) -> Self {
        Self {
            name,
            action,
            apply_required: hot_apply_available,
            restart_required: !hot_apply_available,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct GroupListEntry {
    pub(super) name: String,
    /// Number of `[[outline.uplinks]]` (and legacy top-level `[[uplinks]]`)
    /// carrying `group = name`. Drives the strict-delete gate and the empty-
    /// group hint in the UI.
    pub(super) uplink_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) config: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct GroupsListResponse {
    pub(super) groups: Vec<GroupListEntry>,
}

/// Build a `[[uplink_group]]` table from a payload by serializing to TOML text
/// (which omits `None`) and re-parsing. Only fields the operator set land on
/// disk — nothing defaulted.
pub(super) fn payload_to_table(p: &GroupPayload) -> Result<Table, String> {
    let text = toml::to_string(p).map_err(|e| format!("serialize group payload: {e}"))?;
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("render group payload: {e}"))?;
    Ok(doc.as_table().clone())
}

/// PATCH merge: overwrite each field present in `patch` on `existing`, leaving
/// the rest untouched. `name` is identity and is never merged (a PATCH cannot
/// rename a group).
pub(super) fn merge_patch_into_table(
    existing: &mut Table,
    patch: &GroupPayload,
) -> Result<(), String> {
    let text = toml::to_string(patch).map_err(|e| format!("serialize group patch: {e}"))?;
    let doc = text
        .parse::<DocumentMut>()
        .map_err(|e| format!("render group patch: {e}"))?;
    for (key, item) in doc.as_table().iter() {
        if key == "name" {
            continue;
        }
        existing.insert(key, item.clone());
    }
    Ok(())
}

/// Parse a group table back into an `UplinkGroupSection` for validation. Goes
/// via TOML text (like `uplinks_crud::table_to_section`) so serde parses the
/// enums (`LoadBalancingMode`, `RoutingScope`, `OverflowPolicy`) and the nested
/// `ProbeSection` through their existing `Deserialize` impls.
pub(super) fn table_to_section(tbl: &Table) -> Result<UplinkGroupSection, String> {
    let text = render_table_with_arrays(tbl);
    toml::from_str::<UplinkGroupSection>(&text).map_err(|e| e.to_string())
}

#[cfg(test)]
#[path = "tests/payload.rs"]
mod tests;
