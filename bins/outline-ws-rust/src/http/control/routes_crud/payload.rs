//! Wire types + TOML conversion for `/control/routes`.
//!
//! A `[[route]]` rule has no identity key — it is addressed by its index in
//! the top-level `route` array. `revision` is a content hash of that array,
//! sent back on every mutation so a stale index (a concurrent edit shifted the
//! rows) is rejected with 409 instead of moving the wrong rule.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use toml_edit::{Array, ArrayOfTables, Item, Table};

use crate::http::control::config_edit::render_table_with_arrays;

/// Mirrors `crate::config::RouteSection`; every field optional. Paths arrive as
/// JSON strings (deserialized into `PathBuf` only later, when the rendered TOML
/// is re-parsed as `RouteSection`). `deny_unknown_fields` so a mistyped key is
/// a 400, not a silently-dropped rule.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RoutePayload {
    pub(super) prefixes: Option<Vec<String>>,
    pub(super) file: Option<String>,
    pub(super) files: Option<Vec<String>>,
    pub(super) domains: Option<Vec<String>>,
    pub(super) domain_file: Option<String>,
    pub(super) domain_files: Option<Vec<String>>,
    pub(super) file_poll_secs: Option<u64>,
    pub(super) default: Option<bool>,
    pub(super) via: Option<String>,
    pub(super) fallback_via: Option<String>,
    pub(super) fallback_direct: Option<bool>,
    pub(super) fallback_drop: Option<bool>,
    pub(super) invert: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateBody {
    pub(super) rule: RoutePayload,
    /// Insert position; `None` → append just before the `default` rule.
    pub(super) at_index: Option<usize>,
    pub(super) revision: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpdateBody {
    pub(super) index: usize,
    pub(super) rule: RoutePayload,
    pub(super) revision: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteBody {
    pub(super) index: usize,
    pub(super) revision: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReorderBody {
    pub(super) from: usize,
    pub(super) to: usize,
    pub(super) revision: String,
}

#[derive(Debug, Serialize)]
pub(super) struct RouteListEntry {
    pub(super) index: usize,
    pub(super) is_default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) config: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(super) struct RoutesListResponse {
    pub(super) routes: Vec<RouteListEntry>,
    pub(super) groups: Vec<String>,
    pub(super) revision: String,
}

#[derive(Debug, Serialize)]
pub(super) struct MutationResponse {
    pub(super) action: &'static str,
    pub(super) index: usize,
    pub(super) apply_required: bool,
    pub(super) restart_required: bool,
    pub(super) revision: String,
}

impl MutationResponse {
    pub(super) fn staged(
        action: &'static str,
        index: usize,
        hot_apply_available: bool,
        revision: String,
    ) -> Self {
        Self {
            action,
            index,
            apply_required: hot_apply_available,
            restart_required: !hot_apply_available,
            revision,
        }
    }
}

fn str_array(values: &[String]) -> toml_edit::Value {
    let mut arr = Array::new();
    for v in values {
        arr.push(v.as_str());
    }
    toml_edit::Value::Array(arr)
}

/// Build a `[[route]]` table from a payload. Only `Some` fields are emitted, so
/// a rule carries exactly what the operator set — nothing defaulted onto disk.
pub(super) fn payload_to_table(p: &RoutePayload) -> Table {
    let mut t = Table::new();
    if let Some(v) = &p.prefixes {
        t.insert("prefixes", Item::Value(str_array(v)));
    }
    if let Some(v) = &p.file {
        t.insert("file", Item::Value(v.as_str().into()));
    }
    if let Some(v) = &p.files {
        t.insert("files", Item::Value(str_array(v)));
    }
    if let Some(v) = &p.domains {
        t.insert("domains", Item::Value(str_array(v)));
    }
    if let Some(v) = &p.domain_file {
        t.insert("domain_file", Item::Value(v.as_str().into()));
    }
    if let Some(v) = &p.domain_files {
        t.insert("domain_files", Item::Value(str_array(v)));
    }
    if let Some(v) = p.file_poll_secs {
        t.insert("file_poll_secs", Item::Value((v as i64).into()));
    }
    if let Some(v) = p.default {
        t.insert("default", Item::Value(v.into()));
    }
    if let Some(v) = &p.via {
        t.insert("via", Item::Value(v.as_str().into()));
    }
    if let Some(v) = &p.fallback_via {
        t.insert("fallback_via", Item::Value(v.as_str().into()));
    }
    if let Some(v) = p.fallback_direct {
        t.insert("fallback_direct", Item::Value(v.into()));
    }
    if let Some(v) = p.fallback_drop {
        t.insert("fallback_drop", Item::Value(v.into()));
    }
    if let Some(v) = p.invert {
        t.insert("invert", Item::Value(v.into()));
    }
    t
}

/// Is this table the `default = true` rule?
pub(super) fn table_is_default(t: &Table) -> bool {
    t.get("default").and_then(|i| i.as_bool()).unwrap_or(false)
}

/// FNV-1a (64-bit) over the rendered array text. Deterministic and
/// dependency-free — enough to detect a concurrent edit between a GET and a
/// mutation. Not security-sensitive.
pub(super) fn route_revision(arr: &ArrayOfTables) -> String {
    let mut doc = toml_edit::DocumentMut::new();
    let mut aot = ArrayOfTables::new();
    for t in arr.iter() {
        aot.push(t.clone());
    }
    doc.insert("route", Item::ArrayOfTables(aot));
    let text = doc.to_string();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// One `RouteListEntry`'s `config` object from its on-disk table.
pub(super) fn route_table_to_json(t: &Table) -> Option<Value> {
    let text = render_table_with_arrays(t);
    let toml_value: toml::Value = toml::from_str(&text).ok()?;
    serde_json::to_value(toml_value).ok()
}

#[cfg(test)]
#[path = "tests/payload.rs"]
mod tests;
