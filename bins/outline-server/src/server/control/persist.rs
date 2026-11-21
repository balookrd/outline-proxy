//! Config file patching for the `users` and server configuration sections.
//!
//! A control-plane mutation touches only the targeted sections/users via
//! [`toml_edit`] instead of re-serializing the whole document. That keeps
//! comments, formatting, untouched sections and `[[users]]` intact.
//!
//! The result is validated with [`crate::config::parse_and_validate`] and
//! written atomically (temp file + rename, mode and owner carried over).

use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use crate::config::{CipherKind, EndpointKind, UserEntry};
use outline_net::fs_util::atomic_write;

use super::manager::FieldPatch;

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

    match doc.get("users") {
        None | Some(Item::None) => {
            let UserMutation::Upsert(entry) = mutation else {
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
                None => users.push(rendered),
            }
        },
    }
    Ok(())
}

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

fn rendered_user(entry: &UserEntry) -> Result<Table> {
    let doc =
        toml_edit::ser::to_document(entry).context("failed to serialize user entry as TOML")?;
    Ok(doc.as_table().clone())
}

fn table_id(table: &Table) -> Option<&str> {
    table.get("id").and_then(Item::as_str)
}

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

fn renders_same(current: &Item, wanted: &Item) -> bool {
    current.to_string().trim() == wanted.to_string().trim()
}

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
                table.set_position(Some(position));
            }
            Item::Table(table)
        },
        (_, wanted) => wanted,
    }
}

fn inline_to_table(inline: InlineTable) -> Table {
    let mut table = inline.into_table();
    table.set_implicit(false);
    table
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerConfigPatch {
    #[serde(default)]
    pub cluster: FieldPatch<ClusterConfigPatch>,
    #[serde(default)]
    pub server: FieldPatch<ServerListenerPatch>,
    #[serde(default)]
    pub shadowsocks: FieldPatch<ShadowsocksPatch>,
    #[serde(default)]
    pub http_root: FieldPatch<HttpRootPatch>,
    #[serde(default)]
    pub access_keys: FieldPatch<AccessKeysPatch>,
    #[serde(default)]
    pub session_resumption: FieldPatch<SessionResumptionPatch>,
    #[serde(default)]
    pub outbound: FieldPatch<OutboundPatch>,
    #[serde(default)]
    pub padding: FieldPatch<PaddingConfigPatch>,
    #[serde(default)]
    pub http_fallback: FieldPatch<HttpFallbackPatch>,
    #[serde(default)]
    pub sni_fallback: FieldPatch<SniFallbackPatch>,
    #[serde(default)]
    pub tuning_profile: FieldPatch<String>,
    #[serde(default)]
    pub tuning: FieldPatch<TuningPatch>,
    #[serde(default)]
    pub endpoints: FieldPatch<Vec<EndpointPatch>>,
}

impl ServerConfigPatch {
    /// Returns true if the patch changes anything outside `[access_keys]`.
    pub fn touches_runtime_settings(&self) -> bool {
        !self.cluster.is_missing()
            || !self.server.is_missing()
            || !self.shadowsocks.is_missing()
            || !self.http_root.is_missing()
            || !self.session_resumption.is_missing()
            || !self.outbound.is_missing()
            || !self.padding.is_missing()
            || !self.http_fallback.is_missing()
            || !self.sni_fallback.is_missing()
            || !self.tuning_profile.is_missing()
            || !self.tuning.is_missing()
            || !self.endpoints.is_missing()
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClusterConfigPatch {
    #[serde(default)]
    pub enabled: FieldPatch<bool>,
    #[serde(default)]
    pub shard_id: FieldPatch<u8>,
    #[serde(default)]
    pub cluster_psk: FieldPatch<String>,
    #[serde(default)]
    pub mesh_listen: FieldPatch<String>,
    #[serde(default)]
    pub mesh_relay_budget_ms: FieldPatch<u64>,
    #[serde(default)]
    pub peers: FieldPatch<Vec<ClusterPeerPatch>>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClusterPeerPatch {
    pub shard: u8,
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TlsCertDto {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerListenerPatch {
    #[serde(default)]
    pub listen: FieldPatch<String>,
    #[serde(default)]
    pub cert_path: FieldPatch<String>,
    #[serde(default)]
    pub key_path: FieldPatch<String>,
    #[serde(default)]
    pub max_connections_per_ip: FieldPatch<usize>,
    #[serde(default)]
    pub certs: FieldPatch<Vec<TlsCertDto>>,
    #[serde(default)]
    pub h3_listen: FieldPatch<String>,
    #[serde(default)]
    pub h3_cert_path: FieldPatch<String>,
    #[serde(default)]
    pub h3_key_path: FieldPatch<String>,
    #[serde(default)]
    pub h3_certs: FieldPatch<Vec<TlsCertDto>>,
    #[serde(default)]
    pub h3_alpn: FieldPatch<Vec<String>>,
    #[serde(default)]
    pub h3_initial_mtu: FieldPatch<u16>,
    #[serde(default)]
    pub h3_mtu_first_probe: FieldPatch<u16>,
    #[serde(default)]
    pub h3_udp_datagrams: FieldPatch<bool>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShadowsocksPatch {
    #[serde(default)]
    pub method: FieldPatch<CipherKind>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpRootPatch {
    #[serde(default)]
    pub auth: FieldPatch<bool>,
    #[serde(default)]
    pub realm: FieldPatch<String>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccessKeysPatch {
    #[serde(default)]
    pub public_host: FieldPatch<String>,
    #[serde(default)]
    pub public_scheme: FieldPatch<String>,
    #[serde(default)]
    pub url_base: FieldPatch<String>,
    #[serde(default)]
    pub file_extension: FieldPatch<String>,
    #[serde(default)]
    pub write_dir: FieldPatch<String>,
    #[serde(default)]
    pub nodes: FieldPatch<Vec<String>>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionResumptionPatch {
    #[serde(default)]
    pub enabled: FieldPatch<bool>,
    #[serde(default)]
    pub orphan_ttl_tcp_secs: FieldPatch<u64>,
    #[serde(default)]
    pub orphan_ttl_udp_secs: FieldPatch<u64>,
    #[serde(default)]
    pub orphan_per_user_cap: FieldPatch<usize>,
    #[serde(default)]
    pub orphan_global_cap: FieldPatch<usize>,
    #[serde(default)]
    pub downlink_buffer_bytes: FieldPatch<usize>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutboundPatch {
    #[serde(default)]
    pub prefer_ipv4: FieldPatch<bool>,
    #[serde(default)]
    pub ipv6_prefix: FieldPatch<String>,
    #[serde(default)]
    pub ipv6_interface: FieldPatch<String>,
    #[serde(default)]
    pub ipv6_prefix_interface: FieldPatch<String>,
    #[serde(default)]
    pub ipv6_refresh_secs: FieldPatch<u64>,
    #[serde(default)]
    pub ipv6_sticky: FieldPatch<bool>,
    #[serde(default)]
    pub ipv6_sticky_ttl_secs: FieldPatch<u64>,
    #[serde(default)]
    pub block_private_ips: FieldPatch<bool>,
    #[serde(default)]
    pub allowed_subnets: FieldPatch<Vec<String>>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PaddingConfigPatch {
    #[serde(default)]
    pub min_bytes: FieldPatch<u16>,
    #[serde(default)]
    pub max_bytes: FieldPatch<u16>,
    #[serde(default)]
    pub cover: FieldPatch<bool>,
    #[serde(default)]
    pub cover_jitter_min_ms: FieldPatch<u64>,
    #[serde(default)]
    pub cover_jitter_max_ms: FieldPatch<u64>,
    #[serde(default)]
    pub throttle_detect_enabled: FieldPatch<bool>,
    #[serde(default)]
    pub throttle_ratio_percent: FieldPatch<u32>,
    #[serde(default)]
    pub throttle_window_secs: FieldPatch<u64>,
    #[serde(default)]
    pub throttle_sustain_windows: FieldPatch<u32>,
    #[serde(default)]
    pub throttle_min_bytes_per_sec: FieldPatch<u64>,
    #[serde(default)]
    pub throttle_signal_cooldown_secs: FieldPatch<u64>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpFallbackPatch {
    #[serde(default)]
    pub backend: FieldPatch<String>,
    #[serde(default)]
    pub request_timeout_secs: FieldPatch<u64>,
    #[serde(default)]
    pub add_x_forwarded_for: FieldPatch<bool>,
    #[serde(default)]
    pub add_x_forwarded_proto: FieldPatch<bool>,
    #[serde(default)]
    pub add_x_forwarded_host: FieldPatch<bool>,
    #[serde(default)]
    pub proxy_protocol: FieldPatch<String>,
    #[serde(default)]
    pub backend_proto: FieldPatch<String>,
    #[serde(default)]
    pub apply_to_h1: FieldPatch<bool>,
    #[serde(default)]
    pub apply_to_h3: FieldPatch<bool>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SniFallbackPatch {
    #[serde(default)]
    pub match_sni: FieldPatch<Vec<String>>,
    #[serde(default)]
    pub allow_no_sni: FieldPatch<bool>,
    #[serde(default)]
    pub max_client_hello_bytes: FieldPatch<usize>,
    #[serde(default)]
    pub backends: FieldPatch<Vec<SniBackendPatch>>,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SniBackendPatch {
    pub backend: String,
    #[serde(default)]
    pub proxy_protocol: Option<String>,
    #[serde(default)]
    pub match_sni: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TuningPatch {
    #[serde(default)]
    pub h2_stream_window_bytes: FieldPatch<u32>,
    #[serde(default)]
    pub h2_connection_window_bytes: FieldPatch<u32>,
    #[serde(default)]
    pub h2_max_send_buf_size: FieldPatch<usize>,
    #[serde(default)]
    pub h3_stream_window_bytes: FieldPatch<u64>,
    #[serde(default)]
    pub h3_connection_window_bytes: FieldPatch<u64>,
    #[serde(default)]
    pub h3_max_concurrent_bidi_streams: FieldPatch<u32>,
    #[serde(default)]
    pub h3_max_concurrent_uni_streams: FieldPatch<u32>,
    #[serde(default)]
    pub h3_write_buffer_bytes: FieldPatch<usize>,
    #[serde(default)]
    pub h3_max_backpressure_bytes: FieldPatch<usize>,
    #[serde(default)]
    pub h3_udp_socket_buffer_bytes: FieldPatch<usize>,
    #[serde(default)]
    pub client_active_ttl_secs: FieldPatch<u64>,
    #[serde(default)]
    pub udp_nat_idle_timeout_secs: FieldPatch<u64>,
    #[serde(default)]
    pub udp_nat_max_entries: FieldPatch<usize>,
    #[serde(default)]
    pub udp_nat_max_entries_per_user: FieldPatch<usize>,
    #[serde(default)]
    pub udp_max_concurrent_relay_tasks: FieldPatch<usize>,
    #[serde(default)]
    pub udp_replay_max_sessions: FieldPatch<usize>,
    #[serde(default)]
    pub udp_replay_max_sessions_per_user: FieldPatch<usize>,
    #[serde(default)]
    pub tcp_handshake_replay_max_salts: FieldPatch<usize>,
    #[serde(default)]
    pub xhttp_max_sessions: FieldPatch<usize>,
    #[serde(default)]
    pub xhttp_max_sessions_per_ip: FieldPatch<usize>,
    #[serde(default)]
    pub xhttp_max_concurrent_relay_tasks: FieldPatch<usize>,
    #[serde(default)]
    pub dns_cache_max_entries: FieldPatch<usize>,
    #[serde(default)]
    pub ws_data_channel_capacity: FieldPatch<usize>,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EndpointPatch {
    pub path: String,
    #[serde(default)]
    pub kind: Option<EndpointKind>,
    pub padded: bool,
}

#[derive(Debug)]
pub(super) enum PersistConfigError {
    Validation(anyhow::Error),
    Io(anyhow::Error),
}

impl std::fmt::Display for PersistConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(err) | Self::Io(err) => write!(f, "{err:#}"),
        }
    }
}

pub(super) fn persist_config_patch(
    path: &Path,
    patch: &ServerConfigPatch,
) -> std::result::Result<bool, PersistConfigError> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))
        .map_err(PersistConfigError::Io)?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let new_contents = match ext {
        "toml" | "" => {
            patch_toml_config(&contents, patch).map_err(PersistConfigError::Validation)?
        },
        other => {
            return Err(PersistConfigError::Io(anyhow::anyhow!(
                "unsupported config file extension: {other:?}"
            )));
        },
    };
    if new_contents == contents {
        return Ok(false);
    }
    crate::config::parse_and_validate(&new_contents)
        .context("patched configuration failed validation")
        .map_err(PersistConfigError::Validation)?;
    atomic_write(path, new_contents.as_bytes()).map_err(PersistConfigError::Io)?;
    Ok(true)
}

fn patch_toml_config(original: &str, patch: &ServerConfigPatch) -> Result<String> {
    let mut doc: DocumentMut = original.parse().context("failed to parse existing TOML config")?;

    // 1. Cluster
    patch_section(&mut doc, "cluster", &patch.cluster, |table, cluster| {
        apply_bool(table, "enabled", &cluster.enabled);
        apply_int(table, "shard_id", &cluster.shard_id);
        match &cluster.cluster_psk {
            FieldPatch::Missing => {},
            FieldPatch::Set(None) => {
                table.remove("cluster_psk");
            },
            FieldPatch::Set(Some(psk)) => {
                let trimmed = psk.trim();
                if trimmed.is_empty() {
                    table.remove("cluster_psk");
                } else if trimmed != "********" {
                    table.insert("cluster_psk", Item::Value(trimmed.into()));
                }
            },
        }
        apply_str(table, "mesh_listen", &cluster.mesh_listen);
        apply_int(table, "mesh_relay_budget_ms", &cluster.mesh_relay_budget_ms);
        match &cluster.peers {
            FieldPatch::Missing => {},
            FieldPatch::Set(None) => {
                table.remove("peers");
            },
            FieldPatch::Set(Some(peers)) => {
                let mut arr = Array::new();
                for p in peers {
                    let mut inline = InlineTable::new();
                    inline.insert("shard", (p.shard as i64).into());
                    inline.insert("addr", p.addr.trim().into());
                    arr.push(Value::InlineTable(inline));
                }
                table.insert("peers", Item::Value(Value::Array(arr)));
            },
        }
    });

    // 2. Server & H3
    patch_section(&mut doc, "server", &patch.server, |table, server| {
        apply_str(table, "listen", &server.listen);
        // If legacy tls_cert_path / tls_key_path keys existed, remove them when
        // writing canonical cert_path / key_path to prevent duplicate-alias errors.
        if !server.cert_path.is_missing() {
            table.remove("tls_cert_path");
            apply_str(table, "cert_path", &server.cert_path);
        }
        if !server.key_path.is_missing() {
            table.remove("tls_key_path");
            apply_str(table, "key_path", &server.key_path);
        }
        apply_int(table, "max_connections_per_ip", &server.max_connections_per_ip);
        apply_certs(table, "certs", &server.certs);

        let touches_h3 = !server.h3_listen.is_missing()
            || !server.h3_cert_path.is_missing()
            || !server.h3_key_path.is_missing()
            || !server.h3_certs.is_missing()
            || !server.h3_alpn.is_missing()
            || !server.h3_initial_mtu.is_missing()
            || !server.h3_mtu_first_probe.is_missing()
            || !server.h3_udp_datagrams.is_missing();

        if touches_h3 {
            if !table.contains_key("h3") || !table["h3"].is_table() {
                let mut h3_tbl = Table::new();
                h3_tbl.set_implicit(false);
                table.insert("h3", Item::Table(h3_tbl));
            }
            let h3_table = table["h3"].as_table_mut().expect("h3 table ensured");
            apply_str(h3_table, "listen", &server.h3_listen);
            apply_str(h3_table, "cert_path", &server.h3_cert_path);
            apply_str(h3_table, "key_path", &server.h3_key_path);
            apply_certs(h3_table, "certs", &server.h3_certs);
            apply_str_list(h3_table, "alpn", &server.h3_alpn, false);
            apply_int(h3_table, "initial_mtu", &server.h3_initial_mtu);
            apply_int(h3_table, "mtu_first_probe", &server.h3_mtu_first_probe);
            apply_bool(h3_table, "udp_datagrams", &server.h3_udp_datagrams);
            if h3_table.is_empty() {
                table.remove("h3");
            }
        }
    });

    // 3. Shadowsocks default method
    patch_section(&mut doc, "shadowsocks", &patch.shadowsocks, |table, ss| match ss.method {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            table.remove("method");
        },
        FieldPatch::Set(Some(kind)) => {
            table.insert("method", Item::Value(kind.as_str().into()));
        },
    });

    // 4. HTTP root auth
    patch_section(&mut doc, "http_root", &patch.http_root, |table, hr| {
        apply_bool(table, "auth", &hr.auth);
        apply_str(table, "realm", &hr.realm);
    });

    // 5. Access keys
    patch_section(&mut doc, "access_keys", &patch.access_keys, |table, ak| {
        apply_str(table, "public_host", &ak.public_host);
        apply_str(table, "public_scheme", &ak.public_scheme);
        apply_str(table, "url_base", &ak.url_base);
        apply_str(table, "file_extension", &ak.file_extension);
        apply_str(table, "write_dir", &ak.write_dir);
        apply_str_list(table, "nodes", &ak.nodes, false);
    });

    // 6. Session Resumption
    patch_section(&mut doc, "session_resumption", &patch.session_resumption, |table, sr| {
        apply_bool(table, "enabled", &sr.enabled);
        apply_int(table, "orphan_ttl_tcp_secs", &sr.orphan_ttl_tcp_secs);
        apply_int(table, "orphan_ttl_udp_secs", &sr.orphan_ttl_udp_secs);
        apply_int(table, "orphan_per_user_cap", &sr.orphan_per_user_cap);
        apply_int(table, "orphan_global_cap", &sr.orphan_global_cap);
        apply_int(table, "downlink_buffer_bytes", &sr.downlink_buffer_bytes);
    });

    // 7. Outbound
    patch_section(&mut doc, "outbound", &patch.outbound, |table, outbound| {
        apply_bool(table, "prefer_ipv4", &outbound.prefer_ipv4);
        apply_str(table, "ipv6_prefix", &outbound.ipv6_prefix);
        apply_str(table, "ipv6_interface", &outbound.ipv6_interface);
        apply_str(table, "ipv6_prefix_interface", &outbound.ipv6_prefix_interface);
        apply_int(table, "ipv6_refresh_secs", &outbound.ipv6_refresh_secs);
        apply_bool(table, "ipv6_sticky", &outbound.ipv6_sticky);
        apply_int(table, "ipv6_sticky_ttl_secs", &outbound.ipv6_sticky_ttl_secs);
        apply_bool(table, "block_private_ips", &outbound.block_private_ips);
        apply_str_list(table, "allowed_subnets", &outbound.allowed_subnets, true);
    });

    // 8. Padding
    patch_section(&mut doc, "padding", &patch.padding, |table, p| {
        apply_int(table, "min_bytes", &p.min_bytes);
        apply_int(table, "max_bytes", &p.max_bytes);
        apply_bool(table, "cover", &p.cover);
        apply_int(table, "cover_jitter_min_ms", &p.cover_jitter_min_ms);
        apply_int(table, "cover_jitter_max_ms", &p.cover_jitter_max_ms);
        apply_bool(table, "throttle_detect_enabled", &p.throttle_detect_enabled);
        apply_int(table, "throttle_ratio_percent", &p.throttle_ratio_percent);
        apply_int(table, "throttle_window_secs", &p.throttle_window_secs);
        apply_int(table, "throttle_sustain_windows", &p.throttle_sustain_windows);
        apply_int(table, "throttle_min_bytes_per_sec", &p.throttle_min_bytes_per_sec);
        apply_int(table, "throttle_signal_cooldown_secs", &p.throttle_signal_cooldown_secs);
    });

    // 9. HTTP Fallback
    patch_section(&mut doc, "http_fallback", &patch.http_fallback, |table, hf| {
        apply_str(table, "backend", &hf.backend);
        apply_int(table, "request_timeout_secs", &hf.request_timeout_secs);
        apply_bool(table, "add_x_forwarded_for", &hf.add_x_forwarded_for);
        apply_bool(table, "add_x_forwarded_proto", &hf.add_x_forwarded_proto);
        apply_bool(table, "add_x_forwarded_host", &hf.add_x_forwarded_host);
        apply_str(table, "proxy_protocol", &hf.proxy_protocol);
        apply_str(table, "backend_proto", &hf.backend_proto);
        apply_bool(table, "apply_to_h1", &hf.apply_to_h1);
        apply_bool(table, "apply_to_h3", &hf.apply_to_h3);
    });

    // 10. SNI Fallback
    patch_section(&mut doc, "sni_fallback", &patch.sni_fallback, |table, sf| {
        apply_str_list(table, "match_sni", &sf.match_sni, false);
        apply_bool(table, "allow_no_sni", &sf.allow_no_sni);
        apply_int(table, "max_client_hello_bytes", &sf.max_client_hello_bytes);
        match &sf.backends {
            FieldPatch::Missing => {},
            FieldPatch::Set(None) => {
                table.remove("backend");
                table.remove("proxy_protocol");
                table.remove("backends");
            },
            FieldPatch::Set(Some(backends)) => {
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
            },
        }
    });

    // 11. Tuning Profile & Overrides
    match &patch.tuning_profile {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            doc.remove("tuning_profile");
        },
        FieldPatch::Set(Some(profile)) => {
            let trimmed = profile.trim();
            if trimmed.is_empty() {
                doc.remove("tuning_profile");
            } else {
                doc.insert("tuning_profile", Item::Value(trimmed.into()));
            }
        },
    }

    patch_section(&mut doc, "tuning", &patch.tuning, |table, t| {
        apply_int(table, "h2_stream_window_bytes", &t.h2_stream_window_bytes);
        apply_int(table, "h2_connection_window_bytes", &t.h2_connection_window_bytes);
        apply_int(table, "h2_max_send_buf_size", &t.h2_max_send_buf_size);
        apply_int(table, "h3_stream_window_bytes", &t.h3_stream_window_bytes);
        apply_int(table, "h3_connection_window_bytes", &t.h3_connection_window_bytes);
        apply_int(table, "h3_max_concurrent_bidi_streams", &t.h3_max_concurrent_bidi_streams);
        apply_int(table, "h3_max_concurrent_uni_streams", &t.h3_max_concurrent_uni_streams);
        apply_int(table, "h3_write_buffer_bytes", &t.h3_write_buffer_bytes);
        apply_int(table, "h3_max_backpressure_bytes", &t.h3_max_backpressure_bytes);
        apply_int(table, "h3_udp_socket_buffer_bytes", &t.h3_udp_socket_buffer_bytes);
        apply_int(table, "client_active_ttl_secs", &t.client_active_ttl_secs);
        apply_int(table, "udp_nat_idle_timeout_secs", &t.udp_nat_idle_timeout_secs);
        apply_int(table, "udp_nat_max_entries", &t.udp_nat_max_entries);
        apply_int(table, "udp_nat_max_entries_per_user", &t.udp_nat_max_entries_per_user);
        apply_int(table, "udp_max_concurrent_relay_tasks", &t.udp_max_concurrent_relay_tasks);
        apply_int(table, "udp_replay_max_sessions", &t.udp_replay_max_sessions);
        apply_int(table, "udp_replay_max_sessions_per_user", &t.udp_replay_max_sessions_per_user);
        apply_int(table, "tcp_handshake_replay_max_salts", &t.tcp_handshake_replay_max_salts);
        apply_int(table, "xhttp_max_sessions", &t.xhttp_max_sessions);
        apply_int(table, "xhttp_max_sessions_per_ip", &t.xhttp_max_sessions_per_ip);
        apply_int(table, "xhttp_max_concurrent_relay_tasks", &t.xhttp_max_concurrent_relay_tasks);
        apply_int(table, "dns_cache_max_entries", &t.dns_cache_max_entries);
        apply_int(table, "ws_data_channel_capacity", &t.ws_data_channel_capacity);
    });

    // 12. Carrier Endpoints (full CRUD when `kind` is set, or legacy padding toggle)
    match &patch.endpoints {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            doc.remove("endpoint");
        },
        FieldPatch::Set(Some(endpoints)) => {
            let full_replace = endpoints.is_empty() || endpoints.iter().all(|ep| ep.kind.is_some());
            if full_replace {
                replace_endpoints(&mut doc, endpoints)?;
            } else if let Some(item) = doc.get_mut("endpoint") {
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
        },
    }

    Ok(doc.to_string())
}

fn replace_endpoints(doc: &mut DocumentMut, endpoints: &[EndpointPatch]) -> Result<()> {
    if endpoints.is_empty() {
        doc.remove("endpoint");
        return Ok(());
    }
    let mut aot = ArrayOfTables::new();
    for ep in endpoints {
        let kind = ep
            .kind
            .context("endpoint kind is required for full endpoint replacement")?;
        let kind_str = endpoint_kind_str(kind);
        let mut tbl = Table::new();
        tbl.insert("path", Item::Value(ep.path.trim().into()));
        tbl.insert("kind", Item::Value(kind_str.into()));
        tbl.insert("padded", Item::Value(ep.padded.into()));
        aot.push(tbl);
    }
    if doc.contains_key("endpoint") {
        // Preserve the existing section position in the document if present.
        let min_pos = doc["endpoint"]
            .as_array_of_tables()
            .and_then(|existing| existing.iter().filter_map(|t| t.position()).min());
        if let Some(pos) = min_pos {
            for tbl in aot.iter_mut() {
                tbl.set_position(Some(pos));
            }
        }
        doc.insert("endpoint", Item::ArrayOfTables(aot));
    } else {
        let insert_pos = reserve_position_before_users(doc);
        if let Some(pos) = insert_pos {
            for tbl in aot.iter_mut() {
                tbl.set_position(Some(pos));
            }
        }
        doc.insert("endpoint", Item::ArrayOfTables(aot));
    }
    Ok(())
}

pub(super) fn endpoint_kind_str(kind: EndpointKind) -> &'static str {
    match kind {
        EndpointKind::WsSs => "ws_ss",
        EndpointKind::WsSsTcp => "ws_ss_tcp",
        EndpointKind::WsSsUdp => "ws_ss_udp",
        EndpointKind::WsVless => "ws_vless",
        EndpointKind::XhttpSs => "xhttp_ss",
        EndpointKind::XhttpSsTcp => "xhttp_ss_tcp",
        EndpointKind::XhttpSsUdp => "xhttp_ss_udp",
        EndpointKind::XhttpVless => "xhttp_vless",
    }
}

fn patch_section<P>(
    doc: &mut DocumentMut,
    name: &str,
    patch: &FieldPatch<P>,
    apply: impl FnOnce(&mut Table, &P),
) {
    match patch {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            doc.remove(name);
        },
        FieldPatch::Set(Some(inner)) => {
            ensure_table_before_users(doc, name);
            let table = doc[name].as_table_mut().expect("table ensured");
            apply(table, inner);
            if table.is_empty() {
                doc.remove(name);
            }
        },
    }
}

fn ensure_table_before_users(doc: &mut DocumentMut, name: &str) {
    if doc.contains_key(name) && doc[name].is_table() {
        return;
    }
    let insert_pos = reserve_position_before_users(doc);
    let mut tbl = Table::new();
    tbl.set_implicit(false);
    if let Some(pos) = insert_pos {
        tbl.set_position(Some(pos));
    }
    doc.insert(name, Item::Table(tbl));
}

/// Shifts positions of `[[users]]` and any trailing tables by +1 so a newly
/// added top-level section lands before the `[[users]]` block rather than at
/// the bottom of the file.
fn reserve_position_before_users(doc: &mut DocumentMut) -> Option<isize> {
    let min_users_pos = match doc.get("users") {
        Some(Item::ArrayOfTables(aot)) => aot.iter().filter_map(|t| t.position()).min(),
        _ => None,
    }?;

    for (_, item) in doc.iter_mut() {
        shift_item_positions(item, min_users_pos);
    }
    Some(min_users_pos)
}

fn shift_item_positions(item: &mut Item, threshold: isize) {
    match item {
        Item::Table(tbl) => {
            if let Some(pos) = tbl.position()
                && pos >= threshold
            {
                tbl.set_position(Some(pos + 1));
            }
            for (_, child) in tbl.iter_mut() {
                shift_item_positions(child, threshold);
            }
        },
        Item::ArrayOfTables(aot) => {
            for tbl in aot.iter_mut() {
                if let Some(pos) = tbl.position()
                    && pos >= threshold
                {
                    tbl.set_position(Some(pos + 1));
                }
                for (_, child) in tbl.iter_mut() {
                    shift_item_positions(child, threshold);
                }
            }
        },
        _ => {},
    }
}

fn apply_bool(table: &mut Table, key: &str, patch: &FieldPatch<bool>) {
    match patch {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            table.remove(key);
        },
        FieldPatch::Set(Some(v)) => {
            table.insert(key, Item::Value((*v).into()));
        },
    }
}

fn apply_str(table: &mut Table, key: &str, patch: &FieldPatch<String>) {
    match patch {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            table.remove(key);
        },
        FieldPatch::Set(Some(v)) => {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                table.remove(key);
            } else {
                table.insert(key, Item::Value(trimmed.into()));
            }
        },
    }
}

fn apply_int<T>(table: &mut Table, key: &str, patch: &FieldPatch<T>)
where
    T: Copy + TryInto<i64>,
{
    match patch {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            table.remove(key);
        },
        FieldPatch::Set(Some(v)) => {
            if let Ok(n) = (*v).try_into() {
                table.insert(key, Item::Value(n.into()));
            }
        },
    }
}

fn apply_str_list(
    table: &mut Table,
    key: &str,
    patch: &FieldPatch<Vec<String>>,
    keep_empty_array: bool,
) {
    match patch {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            table.remove(key);
        },
        FieldPatch::Set(Some(items)) => {
            let mut arr = Array::new();
            for s in items {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    arr.push(trimmed);
                }
            }
            if arr.is_empty() && !keep_empty_array {
                table.remove(key);
            } else {
                table.insert(key, Item::Value(Value::Array(arr)));
            }
        },
    }
}

fn apply_certs(table: &mut Table, key: &str, patch: &FieldPatch<Vec<TlsCertDto>>) {
    match patch {
        FieldPatch::Missing => {},
        FieldPatch::Set(None) => {
            table.remove(key);
        },
        FieldPatch::Set(Some(certs)) => {
            if certs.is_empty() {
                table.insert(key, Item::Value(Value::Array(Array::new())));
                return;
            }
            let mut aot = ArrayOfTables::new();
            for cert in certs {
                let mut c_table = Table::new();
                c_table.insert("cert_path", Item::Value(cert.cert_path.trim().into()));
                c_table.insert("key_path", Item::Value(cert.key_path.trim().into()));
                if let Some(snis) = &cert.sni {
                    let mut arr = Array::new();
                    for s in snis {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            arr.push(trimmed);
                        }
                    }
                    if !arr.is_empty() {
                        c_table.insert("sni", Item::Value(Value::Array(arr)));
                    }
                }
                aot.push(c_table);
            }
            table.insert(key, Item::ArrayOfTables(aot));
        },
    }
}

#[cfg(test)]
#[path = "tests/persist.rs"]
mod tests;
