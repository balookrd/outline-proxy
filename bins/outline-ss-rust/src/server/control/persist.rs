//! Config file patching for the `users` section.
//!
//! A control-plane mutation touches ONE user, so this patches that one entry in
//! place through [`toml_edit`] instead of re-serializing the user list. The
//! distinction matters twice over:
//!
//! - The file keeps its original shape: `[[users]]` tables stay tables (a
//!   serialized `&[UserEntry]` renders as one inline `users = [{…}, …]` line,
//!   hoisted above every section), key order, comments inside a user's block
//!   and the position of the whole section survive.
//! - Nothing the mutation did not name can be lost. Rewriting the whole list
//!   makes the in-memory registry authoritative over the file, so any user the
//!   runtime does not hold — because it started from a different source, or the
//!   file grew an entry since — is deleted as a side effect of adding one.
//!
//! The result is written atomically (temp file + rename, mode and owner
//! carried over) so a crash mid-write cannot leave a half-written config.

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use crate::config::UserEntry;
use crate::fs_util::atomic_write;

/// One control-plane change to the on-disk user list. Deliberately narrow:
/// there is no "replace the whole list" variant, because that is the operation
/// that loses users. Owned so it can cross into the blocking write task.
pub(super) enum UserMutation {
    /// Patch this user's entry in place, or append it when absent.
    Upsert(Box<UserEntry>),
    /// Drop this user's entry, if the file has one.
    Remove(String),
}

pub(super) fn persist_user_mutation(path: &Path, mutation: &UserMutation) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let new_contents = match ext {
        "toml" | "" => patch_toml(&contents, mutation)?,
        other => bail!("unsupported config file extension: {other:?}"),
    };
    if new_contents == contents {
        // Idempotent mutation (e.g. blocking an already-blocked user): leave the
        // file's mtime alone so config watchers stay quiet.
        return Ok(());
    }
    atomic_write(path, new_contents.as_bytes())
}

fn patch_toml(original: &str, mutation: &UserMutation) -> Result<String> {
    let mut doc: DocumentMut = original.parse().context("failed to parse existing TOML config")?;

    // Which shape the file stores `users` in decides how it is patched. The
    // canonical shape is `[[users]]` tables; the inline array is what older
    // builds of this module left behind, and is patched in its own shape rather
    // than reformatted, so a mutation never rewrites more than it must.
    match doc.get("users") {
        None | Some(Item::None) => {
            let UserMutation::Upsert(entry) = mutation else {
                // Removing a user the file never had: nothing to patch.
                return Ok(doc.to_string());
            };
            let mut users = ArrayOfTables::new();
            users.push(rendered_user(entry)?);
            doc.insert("users", Item::ArrayOfTables(users));
        },
        Some(Item::ArrayOfTables(_)) => {
            let users = doc["users"]
                .as_array_of_tables_mut()
                .expect("matched ArrayOfTables above");
            patch_user_tables(users, mutation)?;
        },
        Some(Item::Value(Value::Array(_))) => {
            let users = doc["users"].as_array_mut().expect("matched Array above");
            patch_inline_users(users, mutation)?;
        },
        Some(_) => bail!(
            "config key `users` is neither an array of `[[users]]` tables nor an array of \
             inline tables; refusing to rewrite it"
        ),
    }
    Ok(doc.to_string())
}

/// Patch the canonical `[[users]]` form.
fn patch_user_tables(users: &mut ArrayOfTables, mutation: &UserMutation) -> Result<()> {
    let index_of = |id: &str| users.iter().position(|t| table_id(t) == Some(id));
    match mutation {
        UserMutation::Remove(id) => {
            if let Some(index) = index_of(id) {
                users.remove(index);
            }
        },
        UserMutation::Upsert(entry) => {
            let rendered = rendered_user(entry)?;
            match index_of(&entry.id) {
                Some(index) => {
                    let existing = users.get_mut(index).expect("index from position");
                    merge_into_table(existing, &rendered);
                },
                // Appending keeps the new table inside the existing `[[users]]`
                // run — toml_edit renders a position-less table right after its
                // siblings, before the next section.
                None => users.push(rendered),
            }
        },
    }
    Ok(())
}

/// Patch the inline `users = [{ … }, … ]` form. Inline tables carry no comments
/// to preserve, so an updated entry is replaced wholesale, keeping only the
/// decor (surrounding whitespace) of the array element it stands in for.
fn patch_inline_users(users: &mut Array, mutation: &UserMutation) -> Result<()> {
    let find = |id: &str| {
        users.iter().position(|value| {
            value
                .as_inline_table()
                .and_then(|t| t.get("id"))
                .and_then(Value::as_str)
                == Some(id)
        })
    };
    match mutation {
        UserMutation::Remove(id) => {
            if let Some(index) = find(id) {
                users.remove(index);
            }
        },
        UserMutation::Upsert(entry) => {
            let mut rendered = Value::InlineTable(rendered_user(entry)?.into_inline_table());
            match find(&entry.id) {
                Some(index) => {
                    if let Some(previous) = users.get(index) {
                        *rendered.decor_mut() = previous.decor().clone();
                    }
                    users.replace(index, rendered);
                },
                None => users.push_formatted(rendered),
            }
        },
    }
    Ok(())
}

/// The user entry as TOML: the fields serde emits for it, in declaration order.
/// This is a *description* of the wanted state, not the text written out —
/// [`merge_into_table`] applies it key by key.
fn rendered_user(entry: &UserEntry) -> Result<Table> {
    let doc =
        toml_edit::ser::to_document(entry).context("failed to serialize user entry as TOML")?;
    Ok(doc.as_table().clone())
}

fn table_id(table: &Table) -> Option<&str> {
    table.get("id").and_then(Item::as_str)
}

/// Apply `src`'s keys onto `dst`, dropping keys `src` no longer has. Unchanged
/// keys are left completely alone; a changed one keeps its key position and its
/// decor, so an inline `# comment` next to a rotated password survives the
/// rotation.
fn merge_into_table(dst: &mut Table, src: &Table) {
    let stale: Vec<String> = dst
        .iter()
        .map(|(key, _)| key.to_owned())
        .filter(|key| src.get(key).is_none())
        .collect();
    for key in stale {
        dst.remove(&key);
    }
    for (key, wanted) in src.iter() {
        let current = dst.get(key);
        if current.is_some_and(|current| renders_same(current, wanted)) {
            continue;
        }
        let shaped = shaped_like(current, wanted.clone());
        dst.insert(key, shaped);
    }
}

/// Whether replacing `current` with `wanted` would change the file at all.
/// Compares rendered text, so a value that differs only in its decor
/// (whitespace, trailing comment) counts as different — harmless, since
/// [`shaped_like`] then carries that decor onto the replacement.
fn renders_same(current: &Item, wanted: &Item) -> bool {
    current.to_string().trim() == wanted.to_string().trim()
}

/// Keep the shape the file already used for this key: decor for a plain value,
/// and a `[users.aliases]` sub-table stays a sub-table rather than collapsing
/// into the inline table serde produces.
fn shaped_like(current: Option<&Item>, wanted: Item) -> Item {
    match (current, wanted) {
        (Some(Item::Value(previous)), Item::Value(mut wanted)) => {
            *wanted.decor_mut() = previous.decor().clone();
            Item::Value(wanted)
        },
        (Some(Item::Table(previous)), Item::Value(Value::InlineTable(inline))) => {
            let mut table = inline_to_table(inline);
            *table.decor_mut() = previous.decor().clone();
            if let Some(position) = previous.position() {
                table.set_position(position);
            }
            Item::Table(table)
        },
        (_, wanted) => wanted,
    }
}

fn inline_to_table(inline: InlineTable) -> Table {
    let mut table = inline.into_table();
    // A sub-table written out as `[users.aliases]` must not be implicit, or
    // toml_edit omits the header and the keys land in the parent table.
    table.set_implicit(false);
    table
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct ServerConfigPatch {
    #[serde(default)]
    pub cluster: Option<ClusterConfigPatch>,
    #[serde(default)]
    pub server: Option<ServerListenerPatch>,
    #[serde(default)]
    pub session_resumption: Option<SessionResumptionPatch>,
    #[serde(default)]
    pub outbound: Option<OutboundPatch>,
    #[serde(default)]
    pub padding: Option<PaddingConfigPatch>,
    #[serde(default)]
    pub http_fallback: Option<HttpFallbackPatch>,
    #[serde(default)]
    pub sni_fallback: Option<SniFallbackPatch>,
    #[serde(default)]
    pub tuning_profile: Option<String>,
    #[serde(default)]
    pub endpoints: Option<Vec<EndpointPatch>>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct ClusterConfigPatch {
    pub enabled: Option<bool>,
    pub shard_id: Option<u8>,
    pub cluster_psk: Option<String>,
    pub mesh_listen: Option<String>,
    pub mesh_relay_budget_ms: Option<u64>,
    pub peers: Option<Vec<ClusterPeerPatch>>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct ClusterPeerPatch {
    pub shard: u8,
    pub addr: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct ServerListenerPatch {
    pub listen: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub h3_listen: Option<String>,
    pub h3_cert_path: Option<String>,
    pub h3_key_path: Option<String>,
    pub h3_initial_mtu: Option<u16>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct SessionResumptionPatch {
    pub enabled: Option<bool>,
    pub orphan_ttl_tcp_secs: Option<u64>,
    pub orphan_ttl_udp_secs: Option<u64>,
    pub orphan_per_user_cap: Option<usize>,
    pub orphan_global_cap: Option<usize>,
    pub downlink_buffer_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct OutboundPatch {
    pub prefer_ipv4: Option<bool>,
    pub ipv6_prefix: Option<String>,
    pub ipv6_interface: Option<String>,
    pub ipv6_prefix_interface: Option<String>,
    pub ipv6_refresh_secs: Option<u64>,
    pub ipv6_sticky: Option<bool>,
    pub ipv6_sticky_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct PaddingConfigPatch {
    pub min_bytes: Option<u16>,
    pub max_bytes: Option<u16>,
    pub cover: Option<bool>,
    pub cover_jitter_min_ms: Option<u64>,
    pub cover_jitter_max_ms: Option<u64>,
    pub throttle_detect_enabled: Option<bool>,
    pub throttle_ratio_percent: Option<u32>,
    pub throttle_window_secs: Option<u64>,
    pub throttle_sustain_windows: Option<u32>,
    pub throttle_min_bytes_per_sec: Option<u64>,
    pub throttle_signal_cooldown_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct HttpFallbackPatch {
    pub backend: Option<String>,
    pub request_timeout_secs: Option<u64>,
    pub add_x_forwarded_for: Option<bool>,
    pub add_x_forwarded_proto: Option<bool>,
    pub add_x_forwarded_host: Option<bool>,
    pub proxy_protocol: Option<String>,
    pub backend_proto: Option<String>,
    pub apply_to_h1: Option<bool>,
    pub apply_to_h3: Option<bool>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(super) struct SniFallbackPatch {
    pub match_sni: Option<Vec<String>>,
    pub allow_no_sni: Option<bool>,
    pub max_client_hello_bytes: Option<usize>,
    pub backends: Option<Vec<SniBackendPatch>>,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub(super) struct SniBackendPatch {
    pub backend: String,
    pub proxy_protocol: Option<String>,
    pub match_sni: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(super) struct EndpointPatch {
    pub path: String,
    pub padded: bool,
}

pub(super) fn persist_config_patch(path: &Path, patch: &ServerConfigPatch) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let new_contents = match ext {
        "toml" | "" => patch_toml_config(&contents, patch)?,
        other => bail!("unsupported config file extension: {other:?}"),
    };
    if new_contents == contents {
        return Ok(());
    }
    atomic_write(path, new_contents.as_bytes())
}

fn patch_toml_config(original: &str, patch: &ServerConfigPatch) -> Result<String> {
    let mut doc: DocumentMut = original.parse().context("failed to parse existing TOML config")?;

    // 1. Cluster
    if let Some(cluster) = &patch.cluster {
        ensure_table(&mut doc, "cluster");
        let table = doc["cluster"].as_table_mut().expect("table ensured");
        if let Some(enabled) = cluster.enabled {
            table.insert("enabled", Item::Value(enabled.into()));
        }
        if let Some(shard_id) = cluster.shard_id {
            table.insert("shard_id", Item::Value((shard_id as i64).into()));
        }
        if let Some(psk) = &cluster.cluster_psk {
            let trimmed = psk.trim();
            if !trimmed.is_empty() && trimmed != "********" {
                table.insert("cluster_psk", Item::Value(trimmed.into()));
            }
        }
        if let Some(listen) = &cluster.mesh_listen {
            table.insert("mesh_listen", Item::Value(listen.trim().into()));
        }
        if let Some(budget) = cluster.mesh_relay_budget_ms {
            table.insert("mesh_relay_budget_ms", Item::Value((budget as i64).into()));
        }
        if let Some(peers) = &cluster.peers {
            let mut arr = Array::new();
            for p in peers {
                let mut inline = InlineTable::new();
                inline.insert("shard", (p.shard as i64).into());
                inline.insert("addr", p.addr.trim().into());
                arr.push(Value::InlineTable(inline));
            }
            table.insert("peers", Item::Value(Value::Array(arr)));
        }
    }

    // 2. Server & H3
    if let Some(server) = &patch.server {
        ensure_table(&mut doc, "server");
        let table = doc["server"].as_table_mut().expect("table ensured");
        if let Some(listen) = &server.listen {
            table.insert("listen", Item::Value(listen.trim().into()));
        }
        if let Some(cert) = &server.cert_path {
            table.insert("cert_path", Item::Value(cert.trim().into()));
        }
        if let Some(key) = &server.key_path {
            table.insert("key_path", Item::Value(key.trim().into()));
        }

        if server.h3_listen.is_some()
            || server.h3_cert_path.is_some()
            || server.h3_key_path.is_some()
            || server.h3_initial_mtu.is_some()
        {
            if !table.contains_key("h3") || !table["h3"].is_table() {
                let mut h3_tbl = Table::new();
                h3_tbl.set_implicit(false);
                table.insert("h3", Item::Table(h3_tbl));
            }
            let h3_table = table["h3"].as_table_mut().expect("h3 table ensured");
            if let Some(h3_listen) = &server.h3_listen {
                h3_table.insert("listen", Item::Value(h3_listen.trim().into()));
            }
            if let Some(cert) = &server.h3_cert_path {
                h3_table.insert("cert_path", Item::Value(cert.trim().into()));
            }
            if let Some(key) = &server.h3_key_path {
                h3_table.insert("key_path", Item::Value(key.trim().into()));
            }
            if let Some(mtu) = server.h3_initial_mtu {
                h3_table.insert("initial_mtu", Item::Value((mtu as i64).into()));
            }
        }
    }

    // 3. Session Resumption
    if let Some(sr) = &patch.session_resumption {
        ensure_table(&mut doc, "session_resumption");
        let table = doc["session_resumption"].as_table_mut().expect("table ensured");
        if let Some(enabled) = sr.enabled {
            table.insert("enabled", Item::Value(enabled.into()));
        }
        if let Some(ttl) = sr.orphan_ttl_tcp_secs {
            table.insert("orphan_ttl_tcp_secs", Item::Value((ttl as i64).into()));
        }
        if let Some(ttl) = sr.orphan_ttl_udp_secs {
            table.insert("orphan_ttl_udp_secs", Item::Value((ttl as i64).into()));
        }
        if let Some(cap) = sr.orphan_per_user_cap {
            table.insert("orphan_per_user_cap", Item::Value((cap as i64).into()));
        }
        if let Some(cap) = sr.orphan_global_cap {
            table.insert("orphan_global_cap", Item::Value((cap as i64).into()));
        }
        if let Some(buf) = sr.downlink_buffer_bytes {
            table.insert("downlink_buffer_bytes", Item::Value((buf as i64).into()));
        }
    }

    // 4. Outbound
    if let Some(outbound) = &patch.outbound {
        ensure_table(&mut doc, "outbound");
        let table = doc["outbound"].as_table_mut().expect("table ensured");
        if let Some(ipv4) = outbound.prefer_ipv4 {
            table.insert("prefer_ipv4", Item::Value(ipv4.into()));
        }
        if let Some(prefix) = &outbound.ipv6_prefix {
            table.insert("ipv6_prefix", Item::Value(prefix.trim().into()));
        }
        if let Some(iface) = &outbound.ipv6_interface {
            table.insert("ipv6_interface", Item::Value(iface.trim().into()));
        }
        if let Some(piface) = &outbound.ipv6_prefix_interface {
            table.insert("ipv6_prefix_interface", Item::Value(piface.trim().into()));
        }
        if let Some(refresh) = outbound.ipv6_refresh_secs {
            table.insert("ipv6_refresh_secs", Item::Value((refresh as i64).into()));
        }
        if let Some(sticky) = outbound.ipv6_sticky {
            table.insert("ipv6_sticky", Item::Value(sticky.into()));
        }
        if let Some(ttl) = outbound.ipv6_sticky_ttl_secs {
            table.insert("ipv6_sticky_ttl_secs", Item::Value((ttl as i64).into()));
        }
    }

    // 5. Padding
    if let Some(p) = &patch.padding {
        ensure_table(&mut doc, "padding");
        let table = doc["padding"].as_table_mut().expect("table ensured");
        if let Some(v) = p.min_bytes {
            table.insert("min_bytes", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.max_bytes {
            table.insert("max_bytes", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.cover {
            table.insert("cover", Item::Value(v.into()));
        }
        if let Some(v) = p.cover_jitter_min_ms {
            table.insert("cover_jitter_min_ms", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.cover_jitter_max_ms {
            table.insert("cover_jitter_max_ms", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.throttle_detect_enabled {
            table.insert("throttle_detect_enabled", Item::Value(v.into()));
        }
        if let Some(v) = p.throttle_ratio_percent {
            table.insert("throttle_ratio_percent", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.throttle_window_secs {
            table.insert("throttle_window_secs", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.throttle_sustain_windows {
            table.insert("throttle_sustain_windows", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.throttle_min_bytes_per_sec {
            table.insert("throttle_min_bytes_per_sec", Item::Value((v as i64).into()));
        }
        if let Some(v) = p.throttle_signal_cooldown_secs {
            table.insert("throttle_signal_cooldown_secs", Item::Value((v as i64).into()));
        }
    }

    // 6. HTTP Fallback
    if let Some(hf) = &patch.http_fallback {
        ensure_table(&mut doc, "http_fallback");
        let table = doc["http_fallback"].as_table_mut().expect("table ensured");
        if let Some(b) = &hf.backend {
            table.insert("backend", Item::Value(b.trim().into()));
        }
        if let Some(v) = hf.request_timeout_secs {
            table.insert("request_timeout_secs", Item::Value((v as i64).into()));
        }
        if let Some(v) = hf.add_x_forwarded_for {
            table.insert("add_x_forwarded_for", Item::Value(v.into()));
        }
        if let Some(v) = hf.add_x_forwarded_proto {
            table.insert("add_x_forwarded_proto", Item::Value(v.into()));
        }
        if let Some(v) = hf.add_x_forwarded_host {
            table.insert("add_x_forwarded_host", Item::Value(v.into()));
        }
        if let Some(v) = &hf.proxy_protocol {
            table.insert("proxy_protocol", Item::Value(v.trim().into()));
        }
        if let Some(v) = &hf.backend_proto {
            table.insert("backend_proto", Item::Value(v.trim().into()));
        }
        if let Some(v) = hf.apply_to_h1 {
            table.insert("apply_to_h1", Item::Value(v.into()));
        }
        if let Some(v) = hf.apply_to_h3 {
            table.insert("apply_to_h3", Item::Value(v.into()));
        }
    }

    // 7. SNI Fallback
    if let Some(sf) = &patch.sni_fallback {
        ensure_table(&mut doc, "sni_fallback");
        let table = doc["sni_fallback"].as_table_mut().expect("table ensured");
        if let Some(match_sni) = &sf.match_sni {
            let mut arr = Array::new();
            for s in match_sni {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    arr.push(trimmed);
                }
            }
            table.insert("match_sni", Item::Value(Value::Array(arr)));
        }
        if let Some(v) = sf.allow_no_sni {
            table.insert("allow_no_sni", Item::Value(v.into()));
        }
        if let Some(v) = sf.max_client_hello_bytes {
            table.insert("max_client_hello_bytes", Item::Value((v as i64).into()));
        }
        if let Some(backends) = &sf.backends {
            table.remove("backend");
            table.remove("proxy_protocol");

            let mut aot = ArrayOfTables::new();
            for b in backends {
                let mut b_table = Table::new();
                b_table.insert("backend", Item::Value(b.backend.trim().into()));
                if let Some(pp) = &b.proxy_protocol {
                    let trimmed = pp.trim();
                    if !trimmed.is_empty() {
                        b_table.insert("proxy_protocol", Item::Value(trimmed.into()));
                    }
                }
                if let Some(match_sni) = &b.match_sni {
                    let mut arr = Array::new();
                    for s in match_sni {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            arr.push(trimmed);
                        }
                    }
                    if !arr.is_empty() {
                        b_table.insert("match_sni", Item::Value(Value::Array(arr)));
                    }
                }
                aot.push(b_table);
            }
            table.insert("backends", Item::ArrayOfTables(aot));
        }
    }

    // 8. Tuning Profile
    if let Some(profile) = &patch.tuning_profile {
        let trimmed = profile.trim();
        if !trimmed.is_empty() {
            doc.insert("tuning_profile", Item::Value(trimmed.into()));
        }
    }

    // 9. Carrier Endpoints
    if let Some(endpoints) = &patch.endpoints
        && let Some(item) = doc.get_mut("endpoint")
    {
        if let Some(aot) = item.as_array_of_tables_mut() {
            for ep in endpoints {
                for tbl in aot.iter_mut() {
                    if tbl.get("path").and_then(Item::as_str) == Some(&ep.path) {
                        tbl.remove("padding");
                        tbl.insert("padded", Item::Value(ep.padded.into()));
                    }
                }
            }
        } else if let Some(arr) = item.as_array_mut() {
            for ep in endpoints {
                for val in arr.iter_mut() {
                    if let Some(inline) = val.as_inline_table_mut()
                        && inline.get("path").and_then(Value::as_str) == Some(&ep.path)
                    {
                        inline.remove("padding");
                        inline.insert("padded", Value::from(ep.padded));
                    }
                }
            }
        }
    }

    Ok(doc.to_string())
}

fn ensure_table(doc: &mut DocumentMut, name: &str) {
    if !doc.contains_key(name) || !doc[name].is_table() {
        let mut tbl = Table::new();
        tbl.set_implicit(false);
        doc.insert(name, Item::Table(tbl));
    }
}

#[cfg(test)]
#[path = "tests/persist.rs"]
mod tests;
