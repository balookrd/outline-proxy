//! Wire types for the `/control/uplinks` CRUD endpoints and the
//! `UplinkPayload ↔ toml_edit::Table ↔ UplinkSection` conversions
//! shared by the create/update handlers.

use serde::{Deserialize, Serialize};
use toml_edit::{Item, Table, Value};

use crate::config::UplinkSection;

/// JSON payload accepted by the CRUD endpoints. Intentionally mirrors
/// `UplinkSection` so users can round-trip config fields. Field semantics
/// match the TOML config (see `config::schema::UplinkSection`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UplinkPayload {
    pub(crate) name: Option<String>,
    pub(crate) transport: Option<String>,
    pub(crate) tcp_ws_url: Option<String>,
    pub(crate) tcp_mode: Option<String>,
    pub(crate) udp_ws_url: Option<String>,
    pub(crate) udp_mode: Option<String>,
    pub(crate) vless_ws_url: Option<String>,
    pub(crate) vless_xhttp_url: Option<String>,
    pub(crate) vless_mode: Option<String>,
    /// VLESS share-link URI; expanded into the matching `vless_*` fields
    /// at load time. Mutually exclusive with the explicit fields. The
    /// `share_link` alias keeps API ergonomics close to other VPN tooling
    /// where the field is commonly named that way.
    #[serde(alias = "share_link")]
    pub(crate) link: Option<String>,
    pub(crate) tcp_addr: Option<String>,
    pub(crate) udp_addr: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) weight: Option<f64>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) ipv6_first: Option<bool>,
    pub(crate) vless_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateBody {
    pub(super) group: String,
    pub(super) uplink: UplinkPayload,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpdateBody {
    pub(super) group: String,
    pub(super) name: String,
    pub(super) patch: UplinkPayload,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteBody {
    pub(super) group: String,
    pub(super) name: String,
}

#[derive(Debug, Serialize)]
pub(super) struct MutationResponse {
    pub(super) group: String,
    pub(super) name: String,
    pub(super) action: &'static str,
    pub(super) restart_required: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct UplinkListEntry {
    pub(super) group: String,
    pub(super) name: String,
    pub(super) index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct UplinkListResponse {
    pub(super) uplinks: Vec<UplinkListEntry>,
}

/// Convert a `toml_edit` table into a `serde_json::Value` by round-tripping
/// through a TOML string. Returns `None` if the round-trip fails (which
/// would be a surprising bug, not a normal user error).
pub(super) fn table_to_json(tbl: &Table) -> Option<serde_json::Value> {
    let text = tbl.to_string();
    let value: toml::Value = toml::from_str(&text).ok()?;
    serde_json::to_value(value).ok()
}

pub(super) fn payload_to_table(payload: &UplinkPayload) -> Table {
    let mut tbl = Table::new();
    fn set_str(tbl: &mut Table, key: &str, value: Option<&str>) {
        if let Some(v) = value {
            tbl.insert(key, Item::Value(Value::from(v)));
        }
    }
    set_str(&mut tbl, "name", payload.name.as_deref());
    set_str(&mut tbl, "transport", payload.transport.as_deref());
    set_str(&mut tbl, "tcp_ws_url", payload.tcp_ws_url.as_deref());
    set_str(&mut tbl, "tcp_mode", payload.tcp_mode.as_deref());
    set_str(&mut tbl, "udp_ws_url", payload.udp_ws_url.as_deref());
    set_str(&mut tbl, "udp_mode", payload.udp_mode.as_deref());
    set_str(&mut tbl, "vless_ws_url", payload.vless_ws_url.as_deref());
    set_str(&mut tbl, "vless_xhttp_url", payload.vless_xhttp_url.as_deref());
    set_str(&mut tbl, "vless_mode", payload.vless_mode.as_deref());
    set_str(&mut tbl, "link", payload.link.as_deref());
    set_str(&mut tbl, "tcp_addr", payload.tcp_addr.as_deref());
    set_str(&mut tbl, "udp_addr", payload.udp_addr.as_deref());
    set_str(&mut tbl, "method", payload.method.as_deref());
    set_str(&mut tbl, "password", payload.password.as_deref());
    if let Some(w) = payload.weight {
        tbl.insert("weight", Item::Value(Value::from(w)));
    }
    if let Some(fw) = payload.fwmark {
        tbl.insert("fwmark", Item::Value(Value::from(fw as i64)));
    }
    if let Some(v) = payload.ipv6_first {
        tbl.insert("ipv6_first", Item::Value(Value::from(v)));
    }
    set_str(&mut tbl, "vless_id", payload.vless_id.as_deref());
    tbl
}

pub(super) fn merge_patch_into_table(tbl: &mut Table, patch: &UplinkPayload) {
    fn set_str(tbl: &mut Table, key: &str, value: Option<&str>) {
        if let Some(v) = value {
            tbl.insert(key, Item::Value(Value::from(v)));
        }
    }
    // `name` is deliberately *not* merged: the identity key lives in the URL
    // body, so a patch cannot rename an uplink. This keeps the write-locked
    // find → mutate path stable.
    if let Some(v) = patch.transport.as_deref() {
        set_str(tbl, "transport", Some(v));
    }
    if let Some(v) = patch.tcp_ws_url.as_deref() {
        set_str(tbl, "tcp_ws_url", Some(v));
    }
    if let Some(v) = patch.tcp_mode.as_deref() {
        set_str(tbl, "tcp_mode", Some(v));
    }
    if let Some(v) = patch.udp_ws_url.as_deref() {
        set_str(tbl, "udp_ws_url", Some(v));
    }
    if let Some(v) = patch.udp_mode.as_deref() {
        set_str(tbl, "udp_mode", Some(v));
    }
    if let Some(v) = patch.vless_ws_url.as_deref() {
        set_str(tbl, "vless_ws_url", Some(v));
    }
    if let Some(v) = patch.vless_xhttp_url.as_deref() {
        set_str(tbl, "vless_xhttp_url", Some(v));
    }
    if let Some(v) = patch.vless_mode.as_deref() {
        set_str(tbl, "vless_mode", Some(v));
    }
    if let Some(v) = patch.link.as_deref() {
        set_str(tbl, "link", Some(v));
    }
    if let Some(v) = patch.tcp_addr.as_deref() {
        set_str(tbl, "tcp_addr", Some(v));
    }
    if let Some(v) = patch.udp_addr.as_deref() {
        set_str(tbl, "udp_addr", Some(v));
    }
    if let Some(v) = patch.method.as_deref() {
        set_str(tbl, "method", Some(v));
    }
    if let Some(v) = patch.password.as_deref() {
        set_str(tbl, "password", Some(v));
    }
    if let Some(w) = patch.weight {
        tbl.insert("weight", Item::Value(Value::from(w)));
    }
    if let Some(fw) = patch.fwmark {
        tbl.insert("fwmark", Item::Value(Value::from(fw as i64)));
    }
    if let Some(v) = patch.ipv6_first {
        tbl.insert("ipv6_first", Item::Value(Value::from(v)));
    }
    if let Some(v) = patch.vless_id.as_deref() {
        set_str(tbl, "vless_id", Some(v));
    }
}

/// Convert the JSON payload to an `UplinkSection` for validation. We go via
/// TOML text so the serde shapes (e.g. `CipherKind`, `ServerAddr`) get
/// parsed through their existing `Deserialize` impls.
pub(super) fn payload_to_section(
    payload: &UplinkPayload,
    fallback_group: Option<&str>,
) -> Result<UplinkSection, String> {
    let mut tbl = payload_to_table(payload);
    if !tbl.contains_key("group") {
        if let Some(g) = fallback_group {
            tbl.insert("group", Item::Value(Value::from(g)));
        }
    }
    table_to_section(&tbl)
}

pub(super) fn table_to_section(tbl: &Table) -> Result<UplinkSection, String> {
    let text = tbl.to_string();
    toml::from_str::<UplinkSection>(&text).map_err(|e| e.to_string())
}
