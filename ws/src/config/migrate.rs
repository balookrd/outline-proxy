//! One-shot on-disk migration of the legacy top-level uplink config shape
//! into the current grouped shape under `[outline]`.
//!
//! Runs before `ConfigFile` deserialization in `load_config`. When any legacy
//! top-level key is detected, the file is rewritten in place with the original
//! preserved as `<path>.bak`. Comments and TOML formatting are lost — this is
//! a temporary migration helper and will be removed together with
//! `compat.rs` once all deployed configs have been migrated.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use tokio::fs;
use toml::Value;
use tracing::{info, warn};

const LEGACY_KEYS: &[&str] = &[
    "transport",
    "tcp_ws_url",
    "tcp_ws_mode",
    "udp_ws_url",
    "udp_ws_mode",
    "tcp_addr",
    "udp_addr",
    "method",
    "password",
    "fwmark",
    "ipv6_first",
    "uplinks",
    "probe",
    "load_balancing",
];

/// Uplink-definition fields (as opposed to probe/load_balancing blocks). When
/// these appear inline without an explicit `[[uplinks]]` array they are folded
/// into a single synthetic `default` uplink — mirroring `compat::synthesize_
/// default_uplink` — so the serialized `[outline]` never mixes scalars and
/// sub-tables (the toml crate mis-serializes that combination).
const UPLINK_INLINE_KEYS: &[&str] = &[
    "transport",
    "tcp_ws_url",
    "tcp_ws_mode",
    "udp_ws_url",
    "udp_ws_mode",
    "tcp_addr",
    "udp_addr",
    "method",
    "password",
    "fwmark",
    "ipv6_first",
];

/// If `raw` contains any legacy top-level uplink keys, rewrite the file on
/// disk (after backing it up) and return the migrated TOML text. When the
/// filesystem is read-only (e.g. systemd `ProtectSystem=strict`), the on-disk
/// rewrite is skipped with a warning and the migrated text is still returned
/// so in-memory loading succeeds. Use `--migrate-config` from a writable
/// context to perform the rewrite.
pub(super) async fn migrate_legacy_config_if_needed(
    path: &Path,
    raw: &str,
) -> Result<Option<String>> {
    let Some(migrated) = migrate_in_memory(path, raw)? else {
        return Ok(None);
    };

    match persist_migrated(path, raw, &migrated).await {
        Ok(()) => {},
        Err(err) if is_readonly_fs_error(&err) => {
            warn!(
                path = %path.display(),
                error = %format_chain(&err),
                "config: detected legacy top-level uplink fields, but the config directory is \
                 not writable; continuing with in-memory migration. To persist the migration, \
                 run `outline-ws-rust --migrate-config --config <path>` from a writable context",
            );
        },
        Err(err) => return Err(err),
    }

    Ok(Some(migrated))
}

/// Explicit on-demand migration. Parses `path`, rewrites the file in place
/// when legacy keys are present, and returns `true` if any change was made.
/// All errors (including read-only filesystem) are propagated — this is meant
/// to be invoked from a context that is expected to be writable.
pub async fn migrate_config_file(path: &Path) -> Result<bool> {
    let raw = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    let Some(migrated) = migrate_in_memory(path, &raw)? else {
        return Ok(false);
    };
    persist_migrated(path, &raw, &migrated).await?;
    Ok(true)
}

fn migrate_in_memory(path: &Path, raw: &str) -> Result<Option<String>> {
    let mut doc: toml::Table =
        toml::from_str(raw).with_context(|| format!("failed to parse {}", path.display()))?;

    if !LEGACY_KEYS.iter().any(|k| doc.contains_key(*k)) {
        return Ok(None);
    }

    let mut legacy = toml::Table::new();
    for key in LEGACY_KEYS {
        if let Some(v) = doc.remove(*key) {
            legacy.insert((*key).to_string(), v);
        }
    }

    let mut outline = match doc.remove("outline") {
        Some(Value::Table(t)) => t,
        Some(_) => bail!("[outline] must be a table"),
        None => toml::Table::new(),
    };
    // Explicit [outline] fields win; top-level fields fill in the gaps.
    for (k, v) in legacy {
        outline.entry(k).or_insert(v);
    }

    // Fold inline uplink-definition fields into a synthetic `default` uplink
    // so the serialized [outline] contains only sub-tables (see the comment
    // on UPLINK_INLINE_KEYS).
    let mut synthetic = toml::Table::new();
    for key in UPLINK_INLINE_KEYS {
        if let Some(v) = outline.remove(*key) {
            synthetic.insert((*key).to_string(), v);
        }
    }
    if !synthetic.is_empty() {
        synthetic.insert("name".to_string(), Value::String("default".to_string()));
        synthetic.entry("weight".to_string()).or_insert(Value::Float(1.0));
        let uplinks_slot = outline
            .entry("uplinks".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        match uplinks_slot {
            Value::Array(arr) if arr.is_empty() => arr.push(Value::Table(synthetic)),
            // If [[uplinks]] already exists, drop the synthetic one — explicit
            // entries already cover the transport config.
            Value::Array(_) => {},
            _ => bail!("[outline.uplinks] must be an array"),
        }
    }

    doc.insert("outline".to_string(), Value::Table(outline));

    let serialized = toml::to_string_pretty(&doc).context("failed to serialize migrated config")?;
    Ok(Some(serialized))
}

async fn persist_migrated(path: &Path, raw: &str, migrated: &str) -> Result<()> {
    let backup = backup_path(path);
    fs::write(&backup, raw)
        .await
        .with_context(|| format!("failed to write backup {}", backup.display()))?;
    fs::write(path, migrated)
        .await
        .with_context(|| format!("failed to write migrated {}", path.display()))?;
    info!(
        path = %path.display(),
        backup = %backup.display(),
        "config: migrated legacy top-level uplink fields into [outline]; original saved as .bak",
    );
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    let mut s = OsString::from(path.as_os_str());
    s.push(".bak");
    PathBuf::from(s)
}

/// Detects read-only / permission errors that should not block startup.
/// Covers EROFS, EACCES, and EPERM anywhere in the anyhow error chain.
fn is_readonly_fs_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|io_err| {
            matches!(
                io_err.kind(),
                io::ErrorKind::ReadOnlyFilesystem | io::ErrorKind::PermissionDenied,
            )
        })
    })
}

fn format_chain(err: &anyhow::Error) -> String {
    let mut out = String::new();
    for (i, cause) in err.chain().enumerate() {
        if i > 0 {
            out.push_str(": ");
        }
        out.push_str(&cause.to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn run(source: &str) -> (Option<String>, String, Option<String>) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, source).await.unwrap();
        let migrated = migrate_legacy_config_if_needed(&path, source).await.unwrap();
        let on_disk = fs::read_to_string(&path).await.unwrap();
        let backup = fs::read_to_string(backup_path(&path)).await.ok();
        (migrated, on_disk, backup)
    }

    #[tokio::test]
    async fn migrates_inline_uplink_fields_into_synthetic_default() {
        let src = "tcp_ws_url = \"wss://example.com/tcp\"\n\
                   method = \"chacha20-ietf-poly1305\"\n\
                   password = \"secret\"\n\n\
                   [probe]\n\
                   interval_secs = 30\n";
        let (migrated, on_disk, backup) = run(src).await;
        let out = migrated.expect("migration should run");
        assert_eq!(out, on_disk);
        assert_eq!(backup.as_deref(), Some(src));
        assert!(out.contains("[outline.probe]"));
        assert!(out.contains("[[outline.uplinks]]"));
        assert!(out.contains("name = \"default\""));
        assert!(out.contains("tcp_ws_url = \"wss://example.com/tcp\""));
        assert!(!out.contains("\n[probe]\n"));
    }

    #[tokio::test]
    async fn migrates_top_level_uplinks_array() {
        let src = "[[uplinks]]\n\
                   name = \"primary\"\n\
                   tcp_ws_url = \"wss://a/tcp\"\n\
                   method = \"chacha20-ietf-poly1305\"\n\
                   password = \"s\"\n\
                   weight = 1.0\n";
        let (_, on_disk, _) = run(src).await;
        assert!(on_disk.contains("[[outline.uplinks]]"));
        assert!(!on_disk.contains("\n[[uplinks]]"));
    }

    #[tokio::test]
    async fn no_op_when_already_grouped() {
        let src = "[outline.probe]\n\
                   interval_secs = 30\n\n\
                   [[outline.uplinks]]\n\
                   name = \"primary\"\n\
                   tcp_ws_url = \"wss://a/tcp\"\n\
                   method = \"chacha20-ietf-poly1305\"\n\
                   password = \"s\"\n\
                   weight = 1.0\n";
        let (migrated, on_disk, backup) = run(src).await;
        assert!(migrated.is_none(), "no migration expected");
        assert_eq!(on_disk, src);
        assert!(backup.is_none(), "no backup should be created");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn readonly_dir_falls_back_to_in_memory_migration() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let src = "tcp_ws_url = \"wss://example.com/tcp\"\n\
                   method = \"chacha20-ietf-poly1305\"\n\
                   password = \"secret\"\n";
        fs::write(&path, src).await.unwrap();

        // Drop write permission on the containing directory so write() fails
        // with EACCES — the closest portable stand-in for EROFS.
        let orig = fs::metadata(dir.path()).await.unwrap().permissions();
        fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let result = migrate_legacy_config_if_needed(&path, src).await;

        // Restore perms so TempDir cleanup works.
        fs::set_permissions(dir.path(), orig).await.unwrap();

        let migrated = result.expect("readonly fs should not fail startup");
        let out = migrated.expect("in-memory migration should have produced text");
        assert!(out.contains("[[outline.uplinks]]"));
        // File on disk is unchanged and no backup was written.
        assert_eq!(fs::read_to_string(&path).await.unwrap(), src);
        assert!(fs::read_to_string(backup_path(&path)).await.is_err());
    }

    #[tokio::test]
    async fn migrate_config_file_rewrites_and_reports_change() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        let src = "tcp_ws_url = \"wss://example.com/tcp\"\n\
                   method = \"chacha20-ietf-poly1305\"\n\
                   password = \"secret\"\n";
        fs::write(&path, src).await.unwrap();

        let changed = migrate_config_file(&path).await.unwrap();
        assert!(changed);
        assert!(
            fs::read_to_string(&path)
                .await
                .unwrap()
                .contains("[[outline.uplinks]]")
        );

        // Second invocation: no change, no error.
        let changed = migrate_config_file(&path).await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn explicit_outline_fields_win_over_top_level() {
        let src = "password = \"legacy\"\n\
                   [outline]\n\
                   password = \"explicit\"\n\
                   tcp_ws_url = \"wss://a/tcp\"\n\
                   method = \"chacha20-ietf-poly1305\"\n";
        let (_, on_disk, _) = run(src).await;
        assert!(on_disk.contains("password = \"explicit\""));
        assert!(!on_disk.contains("password = \"legacy\""));
    }
}
