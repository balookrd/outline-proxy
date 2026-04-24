//! Config file round-trip for the `users` section.
//!
//! Edits only the top-level `users` key: parses the file as a generic value,
//! replaces the `users` array with the current in-memory list, and writes the
//! result back atomically (temp file + rename). Every other field in the
//! config (listeners, TLS paths, tuning overrides, etc.) is preserved
//! byte-for-byte after re-serialization.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::config::UserEntry;

pub(super) fn persist_users(path: &Path, users: &[UserEntry]) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let new_contents = match ext {
        "yaml" | "yml" => rewrite_yaml(&contents, users)?,
        "toml" | "" => rewrite_toml(&contents, users)?,
        other => bail!("unsupported config file extension: {other:?}"),
    };
    atomic_write(path, new_contents.as_bytes())
}

fn rewrite_yaml(original: &str, users: &[UserEntry]) -> Result<String> {
    let mut root: serde_yml::Value =
        serde_yml::from_str(original).context("failed to parse existing YAML config")?;
    let users_value =
        serde_yml::to_value(users).context("failed to serialize users to YAML value")?;
    match &mut root {
        serde_yml::Value::Mapping(map) => {
            map.insert(serde_yml::Value::String("users".to_owned()), users_value);
        },
        serde_yml::Value::Null => {
            let mut map = serde_yml::Mapping::new();
            map.insert(serde_yml::Value::String("users".to_owned()), users_value);
            root = serde_yml::Value::Mapping(map);
        },
        _ => bail!("top-level YAML config must be a mapping"),
    }
    serde_yml::to_string(&root).context("failed to serialize YAML config")
}

fn rewrite_toml(original: &str, users: &[UserEntry]) -> Result<String> {
    let mut root: toml::Value =
        toml::from_str(original).context("failed to parse existing TOML config")?;
    let users_value = toml::Value::try_from(users)
        .context("failed to serialize users to TOML value")?;
    match &mut root {
        toml::Value::Table(table) => {
            table.insert("users".to_owned(), users_value);
        },
        _ => bail!("top-level TOML config must be a table"),
    }
    toml::to_string_pretty(&root).context("failed to serialize TOML config")
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp: PathBuf = {
        let mut t = path.to_path_buf();
        let fname = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".to_owned());
        t.set_file_name(format!(".{fname}.tmp"));
        t
    };
    fs::write(&tmp, bytes)
        .with_context(|| format!("failed to write temp config {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!("failed to rename {} -> {}", tmp.display(), path.display())
    })?;
    Ok(())
}
