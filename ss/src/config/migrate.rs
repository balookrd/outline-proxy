//! Legacy flat-key -> nested-section config migration.
//!
//! Preserves comments and formatting via `toml_edit`. Scheduled for removal
//! once existing deployments have been migrated.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, Value};

use crate::fs_util::atomic_write;

/// If `contents` contains any legacy top-level keys, migrate them, write the
/// result to `path` (after placing a `<path>.bak` backup) and return the
/// migrated text. Otherwise return `Ok(None)`. Used from the regular config
/// loader so services keep running after an in-place upgrade.
pub(super) fn auto_migrate_if_legacy(path: &Path, contents: &str) -> Result<Option<String>> {
    let (migrated, changed) = migrate_str(contents)?;
    if !changed {
        return Ok(None);
    }
    let backup = backup_path(path);
    // Tracing is not yet initialised at config-load time, so use eprintln!
    // directly — systemd/journald still captures stderr.
    match atomic_write(&backup, contents.as_bytes())
        .and_then(|()| atomic_write(path, migrated.as_bytes()))
    {
        Ok(()) => {
            eprintln!(
                "config: migrated legacy flat-key layout in {} (backup: {})",
                path.display(),
                backup.display(),
            );
        },
        Err(error) => {
            let _ = fs::remove_file(&backup);
            eprintln!(
                "config: legacy flat-key layout detected in {path} but the file is \
                 not writable ({error}); migrated in memory only. Run \
                 `outline-ss-rust --migrate-config {path}` from a writable context \
                 to persist.",
                path = path.display(),
                error = error,
            );
        },
    }
    Ok(Some(migrated))
}

fn backup_path(path: &Path) -> std::path::PathBuf {
    path.with_extension(format!(
        "{}.bak",
        path.extension().and_then(|e| e.to_str()).unwrap_or("toml")
    ))
}

/// Migrate legacy top-level keys in `path` into their new sections in place.
///
/// Writes a `<path>.bak` copy before touching the original. Returns `true`
/// if anything was migrated, `false` if the file was already in the new
/// layout (no-op — `.bak` is not written).
pub fn migrate_config_in_place(path: &Path) -> Result<bool> {
    let original =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let (migrated, changed) = migrate_str(&original)?;
    if !changed {
        return Ok(false);
    }
    let backup = backup_path(path);
    atomic_write(&backup, original.as_bytes())
        .with_context(|| format!("failed to write backup {}", backup.display()))?;
    atomic_write(path, migrated.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(true)
}

/// Flat→nested key mapping. `None` target means "handled specially".
const MAPPINGS: &[(&str, &[&str])] = &[
    ("listen", &["server", "listen"]),
    ("tls_cert_path", &["server", "tls_cert_path"]),
    ("tls_key_path", &["server", "tls_key_path"]),
    ("ss_listen", &["server", "ss", "listen"]),
    ("h3_listen", &["server", "h3", "listen"]),
    ("h3_cert_path", &["server", "h3", "cert_path"]),
    ("h3_key_path", &["server", "h3", "key_path"]),
    ("metrics_listen", &["metrics", "listen"]),
    ("metrics_path", &["metrics", "path"]),
    ("prefer_ipv4_upstream", &["outbound", "prefer_ipv4"]),
    ("outbound_ipv6_prefix", &["outbound", "ipv6_prefix"]),
    ("outbound_ipv6_interface", &["outbound", "ipv6_interface"]),
    ("outbound_ipv6_refresh_secs", &["outbound", "ipv6_refresh_secs"]),
    ("ws_path_tcp", &["websocket", "ws_path_tcp"]),
    ("ws_path_udp", &["websocket", "ws_path_udp"]),
    ("ws_path_vless", &["websocket", "ws_path_vless"]),
    ("http_root_auth", &["http_root", "auth"]),
    ("http_root_realm", &["http_root", "realm"]),
    ("public_host", &["access_keys", "public_host"]),
    ("public_scheme", &["access_keys", "public_scheme"]),
    ("access_key_url_base", &["access_keys", "url_base"]),
    ("access_key_file_extension", &["access_keys", "file_extension"]),
    ("print_access_keys", &["access_keys", "print"]),
    ("write_access_keys_dir", &["access_keys", "write_dir"]),
    ("method", &["shadowsocks", "method"]),
];

fn migrate_str(input: &str) -> Result<(String, bool)> {
    let mut doc: DocumentMut = input.parse().context("failed to parse config as TOML")?;
    let mut changed = false;

    for (old_key, path) in MAPPINGS {
        if let Some(item) = doc.as_table_mut().remove(old_key) {
            let value = item.into_value().map_err(|item| {
                anyhow::anyhow!("legacy key {old_key} must be a value, got {item:?}")
            })?;
            insert_at_path(doc.as_table_mut(), path, value)?;
            changed = true;
        }
    }

    // Legacy single-user fallback: synthesise [[users]] entry.
    let legacy_password = doc.as_table_mut().remove("password");
    let legacy_fwmark = doc.as_table_mut().remove("fwmark");
    if let Some(pw_item) = legacy_password {
        let pw_value = pw_item
            .into_value()
            .map_err(|_| anyhow::anyhow!("legacy password must be a string"))?;
        let fwmark_value = legacy_fwmark.and_then(|item| item.into_value().ok());
        append_default_user(doc.as_table_mut(), pw_value, fwmark_value)?;
        changed = true;
    } else if legacy_fwmark.is_some() {
        // Top-level fwmark without password was already dead code; drop it.
        changed = true;
    }

    Ok((doc.to_string(), changed))
}

fn insert_at_path(root: &mut Table, path: &[&str], value: Value) -> Result<()> {
    let (leaf, parents) = path.split_last().expect("non-empty path");
    let mut table = root;
    for segment in parents {
        let entry = table.entry(segment).or_insert_with(|| Item::Table(Table::new()));
        table = entry
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("expected table at {segment}"))?;
        table.set_implicit(false);
    }
    if table.contains_key(leaf) {
        anyhow::bail!("cannot migrate: target key {leaf} already exists");
    }
    table.insert(leaf, Item::Value(value));
    Ok(())
}

fn append_default_user(root: &mut Table, password: Value, fwmark: Option<Value>) -> Result<()> {
    let entry = root
        .entry("users")
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    let array = entry
        .as_array_of_tables_mut()
        .ok_or_else(|| anyhow::anyhow!("`users` is not an array of tables"))?;
    let mut user = Table::new();
    user.insert("id", Item::Value(Value::from("default")));
    user.insert("password", Item::Value(password));
    if let Some(fwmark) = fwmark {
        user.insert("fwmark", Item::Value(fwmark));
    }
    array.push(user);
    Ok(())
}

#[cfg(test)]
#[path = "tests/migrate.rs"]
mod tests;
