//! Wire types for the `/control/uplinks` CRUD endpoints and the
//! `UplinkPayload ↔ toml_edit::Table ↔ UplinkSection` conversions
//! shared by the create/update handlers.

use serde::{Deserialize, Serialize};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value};

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
    /// Per-uplink fallback transports — the wire-shape list rendered as
    /// `[[outline.uplinks.fallbacks]]` in the TOML config. When set in a
    /// PATCH request, the payload **replaces** the entire fallbacks array
    /// (no per-entry merging — fallback identity is positional, so a partial
    /// merge would be ambiguous). To remove all fallbacks, send an empty
    /// array `[]`. Field stays `Option<...>` so omitting it from a PATCH
    /// leaves the existing fallbacks untouched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fallbacks: Option<Vec<FallbackPayload>>,
}

/// JSON wire shape for one fallback wire — same fields as the TOML
/// `[[outline.uplinks.fallbacks]]` block (no `name` / `weight` / `group` /
/// `link`; those belong to the parent uplink). Mirrors
/// `crate::config::schema::FallbackSection`. Validation happens through
/// the same `UplinkSection → ResolvedUplinkInput::try_into` pipeline as
/// the TOML loader, so error messages stay consistent across the two
/// surfaces.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FallbackPayload {
    pub(crate) transport: String,
    pub(crate) tcp_ws_url: Option<String>,
    pub(crate) tcp_mode: Option<String>,
    pub(crate) udp_ws_url: Option<String>,
    pub(crate) udp_mode: Option<String>,
    pub(crate) vless_ws_url: Option<String>,
    pub(crate) vless_xhttp_url: Option<String>,
    pub(crate) vless_mode: Option<String>,
    pub(crate) tcp_addr: Option<String>,
    pub(crate) udp_addr: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) password: Option<String>,
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
    /// Whether clients should call `/control/apply` to activate this
    /// staged config-file change without restarting the process.
    pub(super) apply_required: bool,
    /// Back-compat activation hint for control states that cannot hot-apply.
    pub(super) restart_required: bool,
}

impl MutationResponse {
    pub(super) fn staged(
        group: String,
        name: String,
        action: &'static str,
        hot_apply_available: bool,
    ) -> Self {
        Self {
            group,
            name,
            action,
            apply_required: hot_apply_available,
            restart_required: !hot_apply_available,
        }
    }
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
///
/// `Table::to_string()` alone doesn't render nested
/// `ArrayOfTables` items (the `[[fallbacks]]` arrays under an uplink's
/// inline table) because the array headers need a parent path to render
/// — the table doesn't know its own path until it's part of a document.
/// Wrap in a one-shot synthetic `DocumentMut` so the nested array
/// surfaces in the rendered TOML.
pub(super) fn table_to_json(tbl: &Table) -> Option<serde_json::Value> {
    let text = render_table_with_arrays(tbl);
    let value: toml::Value = toml::from_str(&text).ok()?;
    serde_json::to_value(value).ok()
}

fn render_table_with_arrays(tbl: &Table) -> String {
    let mut doc = DocumentMut::new();
    let root = doc.as_table_mut();
    for (key, item) in tbl.iter() {
        root.insert(key, item.clone());
    }
    doc.to_string()
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
    if let Some(fallbacks) = payload.fallbacks.as_ref() {
        tbl.insert("fallbacks", Item::ArrayOfTables(fallbacks_to_array(fallbacks)));
    }
    tbl
}

/// Build the `[[outline.uplinks.fallbacks]]` array-of-tables that lives
/// under the parent uplink. Each entry mirrors the TOML schema for
/// `FallbackSection`. Empty fields are omitted so the rendered TOML
/// stays minimal and the schema deserializer applies its defaults.
fn fallbacks_to_array(fallbacks: &[FallbackPayload]) -> ArrayOfTables {
    let mut arr = ArrayOfTables::new();
    for fb in fallbacks {
        let mut sub = Table::new();
        fn set_str(tbl: &mut Table, key: &str, value: Option<&str>) {
            if let Some(v) = value {
                tbl.insert(key, Item::Value(Value::from(v)));
            }
        }
        sub.insert("transport", Item::Value(Value::from(fb.transport.as_str())));
        set_str(&mut sub, "tcp_ws_url", fb.tcp_ws_url.as_deref());
        set_str(&mut sub, "tcp_mode", fb.tcp_mode.as_deref());
        set_str(&mut sub, "udp_ws_url", fb.udp_ws_url.as_deref());
        set_str(&mut sub, "udp_mode", fb.udp_mode.as_deref());
        set_str(&mut sub, "vless_ws_url", fb.vless_ws_url.as_deref());
        set_str(&mut sub, "vless_xhttp_url", fb.vless_xhttp_url.as_deref());
        set_str(&mut sub, "vless_mode", fb.vless_mode.as_deref());
        set_str(&mut sub, "tcp_addr", fb.tcp_addr.as_deref());
        set_str(&mut sub, "udp_addr", fb.udp_addr.as_deref());
        set_str(&mut sub, "method", fb.method.as_deref());
        set_str(&mut sub, "password", fb.password.as_deref());
        if let Some(fw) = fb.fwmark {
            sub.insert("fwmark", Item::Value(Value::from(fw as i64)));
        }
        if let Some(v) = fb.ipv6_first {
            sub.insert("ipv6_first", Item::Value(Value::from(v)));
        }
        set_str(&mut sub, "vless_id", fb.vless_id.as_deref());
        arr.push(sub);
    }
    arr
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
    if let Some(fallbacks) = patch.fallbacks.as_ref() {
        // PATCH semantics: a present `fallbacks` field replaces the whole
        // list. Empty array clears all fallbacks. Omitted (`None`) leaves
        // the existing list untouched. See doc comment on
        // `UplinkPayload::fallbacks` for the rationale.
        if fallbacks.is_empty() {
            tbl.remove("fallbacks");
        } else {
            tbl.insert("fallbacks", Item::ArrayOfTables(fallbacks_to_array(fallbacks)));
        }
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
    // See `table_to_json` for why we render through a synthetic document
    // rather than `tbl.to_string()` directly.
    let text = render_table_with_arrays(tbl);
    toml::from_str::<UplinkSection>(&text).map_err(|e| e.to_string())
}
