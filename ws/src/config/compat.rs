//! Configuration compatibility layer.
//!
//! Normalises the two historically accepted shapes of uplink configuration
//! into a single canonical `OutlineSection`:
//!
//! 1. **Legacy flat shape** — uplink fields (`tcp_ws_url`, `method`, …) and
//!    `[[uplinks]]` / `[probe]` / `[load_balancing]` at the file's top level.
//! 2. **Grouped shape** — the same fields nested under `[outline]`.
//!
//! Downstream loaders only ever see the grouped shape. If both are present,
//! the explicit `[outline]` section wins field-by-field (top level acts as a
//! default). Legacy use logs a deprecation warning so operators can migrate.
//!
//! Additionally, when the resulting `OutlineSection` has uplink-definition
//! fields at its root but no explicit `[[uplinks]]`, a single synthetic
//! uplink entry named `default` is inserted so that downstream code only
//! has to iterate `outline.uplinks`.

use tracing::warn;

use super::schema::{ConfigFile, OutlineSection, UplinkSection};

/// Merge legacy top-level fields and the `[outline]` section into a single
/// canonical `OutlineSection`, and ensure `uplinks` is populated whenever
/// any uplink-definition fields are set.
pub(crate) fn normalize_outline_section(file: &ConfigFile) -> Option<OutlineSection> {
    let top_level_present = top_level_uplink_fields_present(file);

    if top_level_present {
        warn!(
            "config: top-level uplink fields (tcp_ws_url/method/password/[[uplinks]]/[probe]/\
             [load_balancing]/…) are deprecated; move them under an explicit [outline] section"
        );
    }

    let merged = match (top_level_present, file.outline.clone()) {
        (false, None) => None,
        (false, Some(outline)) => Some(outline),
        (true, None) => Some(from_top_level(file)),
        (true, Some(outline)) => Some(merge_top_level_into(file, outline)),
    }?;

    Some(synthesize_default_uplink(merged))
}

fn top_level_uplink_fields_present(file: &ConfigFile) -> bool {
    file.tcp_ws_url.is_some()
        || file.transport.is_some()
        || file.tcp_mode.is_some()
        || file.udp_ws_url.is_some()
        || file.udp_mode.is_some()
        || file.vless_ws_url.is_some()
        || file.vless_xhttp_url.is_some()
        || file.vless_mode.is_some()
        || file.link.is_some()
        || file.tcp_addr.is_some()
        || file.udp_addr.is_some()
        || file.method.is_some()
        || file.password.is_some()
        || file.fwmark.is_some()
        || file.ipv6_first.is_some()
        || file.uplinks.is_some()
        || file.probe.is_some()
        || file.load_balancing.is_some()
}

fn from_top_level(file: &ConfigFile) -> OutlineSection {
    OutlineSection {
        transport: file.transport,
        tcp_ws_url: file.tcp_ws_url.clone(),
        tcp_mode: file.tcp_mode,
        udp_ws_url: file.udp_ws_url.clone(),
        udp_mode: file.udp_mode,
        vless_ws_url: file.vless_ws_url.clone(),
        vless_xhttp_url: file.vless_xhttp_url.clone(),
        vless_mode: file.vless_mode,
        link: file.link.clone(),
        tcp_addr: file.tcp_addr.clone(),
        udp_addr: file.udp_addr.clone(),
        method: file.method,
        password: file.password.clone(),
        fwmark: file.fwmark,
        ipv6_first: file.ipv6_first,
        uplinks: file.uplinks.clone(),
        probe: file.probe.clone(),
        load_balancing: file.load_balancing.clone(),
    }
}

fn merge_top_level_into(file: &ConfigFile, outline: OutlineSection) -> OutlineSection {
    OutlineSection {
        transport: outline.transport.or(file.transport),
        tcp_ws_url: outline.tcp_ws_url.or_else(|| file.tcp_ws_url.clone()),
        tcp_mode: outline.tcp_mode.or(file.tcp_mode),
        udp_ws_url: outline.udp_ws_url.or_else(|| file.udp_ws_url.clone()),
        udp_mode: outline.udp_mode.or(file.udp_mode),
        vless_ws_url: outline.vless_ws_url.or_else(|| file.vless_ws_url.clone()),
        vless_xhttp_url: outline.vless_xhttp_url.or_else(|| file.vless_xhttp_url.clone()),
        vless_mode: outline.vless_mode.or(file.vless_mode),
        link: outline.link.or_else(|| file.link.clone()),
        tcp_addr: outline.tcp_addr.or_else(|| file.tcp_addr.clone()),
        udp_addr: outline.udp_addr.or_else(|| file.udp_addr.clone()),
        method: outline.method.or(file.method),
        password: outline.password.or_else(|| file.password.clone()),
        fwmark: outline.fwmark.or(file.fwmark),
        ipv6_first: outline.ipv6_first.or(file.ipv6_first),
        uplinks: outline.uplinks.or_else(|| file.uplinks.clone()),
        probe: outline.probe.or_else(|| file.probe.clone()),
        load_balancing: outline.load_balancing.or_else(|| file.load_balancing.clone()),
    }
}

/// When the outline section declares uplink-definition fields inline but no
/// explicit `[[uplinks]]`, synthesise a single entry named `default` so that
/// downstream code only has to iterate `outline.uplinks`.
fn synthesize_default_uplink(mut outline: OutlineSection) -> OutlineSection {
    if outline.uplinks.is_some() {
        return outline;
    }
    if !outline_has_inline_uplink_fields(&outline) {
        return outline;
    }
    outline.uplinks = Some(vec![UplinkSection {
        name: Some("default".to_string()),
        transport: outline.transport,
        tcp_ws_url: outline.tcp_ws_url.clone(),
        tcp_mode: outline.tcp_mode,
        udp_ws_url: outline.udp_ws_url.clone(),
        udp_mode: outline.udp_mode,
        vless_ws_url: outline.vless_ws_url.clone(),
        vless_xhttp_url: outline.vless_xhttp_url.clone(),
        vless_mode: outline.vless_mode,
        link: outline.link.clone(),
        tcp_addr: outline.tcp_addr.clone(),
        udp_addr: outline.udp_addr.clone(),
        method: outline.method,
        password: outline.password.clone(),
        weight: Some(1.0),
        fwmark: outline.fwmark,
        ipv6_first: outline.ipv6_first,
        vless_id: None,
        group: None,
    }]);
    outline
}

fn outline_has_inline_uplink_fields(outline: &OutlineSection) -> bool {
    outline.transport.is_some()
        || outline.tcp_ws_url.is_some()
        || outline.tcp_mode.is_some()
        || outline.udp_ws_url.is_some()
        || outline.udp_mode.is_some()
        || outline.vless_ws_url.is_some()
        || outline.vless_xhttp_url.is_some()
        || outline.vless_mode.is_some()
        || outline.link.is_some()
        || outline.tcp_addr.is_some()
        || outline.udp_addr.is_some()
        || outline.method.is_some()
        || outline.password.is_some()
        || outline.fwmark.is_some()
        || outline.ipv6_first.is_some()
}
