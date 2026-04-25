use anyhow::{Result, anyhow, bail};

use outline_uplink::{UplinkConfig, UplinkGroupConfig};

use super::super::args::Args;
use super::super::schema::{ConfigFile, LoadBalancingSection, OutlineSection, ProbeSection, UplinkGroupSection};
use super::balancing::load_balancing_config;
use super::probe::load_probe_config;
use super::uplinks::load_uplinks;

pub(super) fn load_groups(
    outline: Option<&OutlineSection>,
    file: Option<&ConfigFile>,
    args: &Args,
) -> Result<Vec<UplinkGroupConfig>> {
    let group_sections = file.and_then(|f| f.uplink_group.as_ref());
    if group_sections.is_none_or(|v| v.is_empty()) {
        // Legacy single-group path — reuse existing flat-config logic.
        let uplinks = load_uplinks(outline, args)?;
        let probe = load_probe_config(outline.and_then(|o| o.probe.as_ref()))?;
        let load_balancing = load_balancing_config(outline.and_then(|o| o.load_balancing.as_ref()))?;
        return Ok(vec![UplinkGroupConfig {
            name: super::DEFAULT_GROUP.to_string(),
            uplinks,
            probe,
            load_balancing,
        }]);
    }

    let sections = group_sections.expect("checked above");
    let probe_template = outline.and_then(|o| o.probe.as_ref()).cloned();

    // Each group becomes a distinct `group` label on every uplink-scoped
    // Prometheus metric; unbounded groups would blow up series cardinality
    // (and with it, scrape memory / disk). Cap well above any realistic
    // deployment (10s of groups at most) but below where cardinality harms.
    const MAX_UPLINK_GROUPS: usize = 64;
    if sections.len() > MAX_UPLINK_GROUPS {
        bail!(
            "too many [[uplink_group]] entries ({}); maximum is {MAX_UPLINK_GROUPS} \
             to bound metric label cardinality",
            sections.len()
        );
    }

    // Validate group names. `name_to_index` gives O(1) duplicate detection
    // here and O(1) lookups further down (per-uplink `group` → index),
    // avoiding what would otherwise be a quadratic scan over uplinks×groups.
    let mut names: Vec<String> = Vec::with_capacity(sections.len());
    let mut name_to_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::with_capacity(sections.len());
    for (index, section) in sections.iter().enumerate() {
        let name = section
            .name
            .clone()
            .ok_or_else(|| anyhow!("[[uplink_group]] entry {} is missing `name`", index + 1))?;
        if name.is_empty() {
            bail!("[[uplink_group]] entry {} has empty name", index + 1);
        }
        if name.eq_ignore_ascii_case(super::DIRECT_TARGET)
            || name.eq_ignore_ascii_case(super::DROP_TARGET)
        {
            bail!("[[uplink_group]].name = \"{name}\" is reserved; pick another name");
        }
        if name_to_index.insert(name.clone(), index).is_some() {
            bail!("duplicate [[uplink_group]] name: {name}");
        }
        names.push(name);
    }

    // Uplinks in new-shape config must live under `outline.uplinks` and carry
    // a `group` field. CLI override still lands everything in the first group
    // (single-uplink CLI convenience).
    let cli_override_requested = args.tcp_ws_url.is_some()
        || args.transport.is_some()
        || args.tcp_ws_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_ws_mode.is_some()
        || args.vless_ws_url.is_some()
        || args.vless_ws_mode.is_some()
        || args.tcp_addr.is_some()
        || args.udp_addr.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some()
        || args.ipv6_first.is_some();
    if cli_override_requested {
        bail!(
            "CLI uplink overrides (--tcp-ws-url / --password / …) are not supported together \
             with [[uplink_group]]: declare the uplink in `[[uplinks]]` instead"
        );
    }

    let uplink_sections = outline.and_then(|o| o.uplinks.as_ref()).cloned().unwrap_or_default();
    if uplink_sections.is_empty() {
        bail!("[[uplink_group]] declared but no [[uplinks]] provided");
    }

    // Group uplinks by their `group` field.
    let mut buckets: Vec<Vec<UplinkConfig>> = vec![Vec::new(); names.len()];
    for (index, uplink) in uplink_sections.iter().enumerate() {
        let group_name = uplink.group.as_ref().ok_or_else(|| {
            anyhow!(
                "[[uplinks]] entry {} is missing `group` (required when [[uplink_group]] is used)",
                index + 1
            )
        })?;
        let group_index = *name_to_index.get(group_name.as_str()).ok_or_else(|| {
            anyhow!(
                "[[uplinks]] entry {} references unknown group \"{group_name}\"",
                index + 1
            )
        })?;
        let resolved: UplinkConfig =
            super::uplinks::ResolvedUplinkInput::from_section(index, uplink).try_into()?;
        buckets[group_index].push(resolved);
    }
    for (name, bucket) in names.iter().zip(&buckets) {
        if bucket.is_empty() {
            bail!("uplink group \"{name}\" has no uplinks assigned");
        }
    }

    // Build each UplinkGroupConfig with merged probe + LB.
    let mut groups = Vec::with_capacity(sections.len());
    for ((section, name), bucket) in sections.iter().zip(names.iter()).zip(buckets.into_iter()) {
        let merged_probe = merge_probe_section(probe_template.as_ref(), section.probe.as_ref());
        let probe = load_probe_config(merged_probe.as_ref())?;
        let load_balancing = load_balancing_config_from_group(section)?;
        groups.push(UplinkGroupConfig {
            name: name.clone(),
            uplinks: bucket,
            probe,
            load_balancing,
        });
    }

    Ok(groups)
}

/// Field-by-field merge of a probe template with a per-group override.
/// Sub-tables (ws/http/dns/tcp) are replaced whole-sale — if the group
/// overrides `[uplink_group.probe.http]`, the template's `[probe.http]` is
/// dropped entirely, not merged field-by-field.
pub(super) fn merge_probe_section(
    template: Option<&ProbeSection>,
    override_: Option<&ProbeSection>,
) -> Option<ProbeSection> {
    match (template, override_) {
        (None, None) => None,
        (Some(t), None) => Some(t.clone()),
        (None, Some(o)) => Some(o.clone()),
        (Some(t), Some(o)) => Some(ProbeSection {
            interval_secs: o.interval_secs.or(t.interval_secs),
            timeout_secs: o.timeout_secs.or(t.timeout_secs),
            max_concurrent: o.max_concurrent.or(t.max_concurrent),
            max_dials: o.max_dials.or(t.max_dials),
            min_failures: o.min_failures.or(t.min_failures),
            attempts: o.attempts.or(t.attempts),
            ws: o.ws.clone().or_else(|| t.ws.clone()),
            http: o.http.clone().or_else(|| t.http.clone()),
            dns: o.dns.clone().or_else(|| t.dns.clone()),
            tcp: o.tcp.clone().or_else(|| t.tcp.clone()),
        }),
    }
}

/// Adapter: build a `LoadBalancingConfig` from the LB fields embedded in
/// `[[uplink_group]]` (same field names / defaults as legacy
/// `[load_balancing]`).
fn load_balancing_config_from_group(section: &UplinkGroupSection) -> Result<outline_uplink::LoadBalancingConfig> {
    let shim = LoadBalancingSection {
        mode: section.mode,
        routing_scope: section.routing_scope,
        sticky_ttl_secs: section.sticky_ttl_secs,
        hysteresis_ms: section.hysteresis_ms,
        failure_cooldown_secs: section.failure_cooldown_secs,
        tcp_chunk0_failover_timeout_secs: section.tcp_chunk0_failover_timeout_secs,
        warm_standby_tcp: section.warm_standby_tcp,
        warm_standby_udp: section.warm_standby_udp,
        rtt_ewma_alpha: section.rtt_ewma_alpha,
        failure_penalty_ms: section.failure_penalty_ms,
        failure_penalty_max_ms: section.failure_penalty_max_ms,
        failure_penalty_halflife_secs: section.failure_penalty_halflife_secs,
        h3_downgrade_secs: section.h3_downgrade_secs,
        udp_ws_keepalive_secs: section.udp_ws_keepalive_secs,
        tcp_ws_standby_keepalive_secs: section.tcp_ws_standby_keepalive_secs,
        tcp_active_keepalive_secs: section.tcp_active_keepalive_secs,
        auto_failback: section.auto_failback,
        vless_udp_max_sessions: section.vless_udp_max_sessions,
        vless_udp_session_idle_secs: section.vless_udp_session_idle_secs,
        vless_udp_janitor_interval_secs: section.vless_udp_janitor_interval_secs,
    };
    load_balancing_config(Some(&shim))
}
