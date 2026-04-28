//! Config file round-trip for the `users` section.
//!
//! We use [`toml_edit`] so comments, key order, and whitespace outside the
//! `users` array are preserved byte-for-byte. Only the `users` key itself is
//! replaced.
//!
//! The result is written atomically (temp file + rename) to avoid leaving a
//! half-written config on disk if the process is killed mid-write.

use std::{fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};

use crate::config::UserEntry;
use crate::fs_util::atomic_write;

pub(super) fn persist_users(path: &Path, users: &[UserEntry]) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let new_contents = match ext {
        "toml" | "" => rewrite_toml(&contents, users)?,
        other => bail!("unsupported config file extension: {other:?}"),
    };
    atomic_write(path, new_contents.as_bytes())
}

fn rewrite_toml(original: &str, users: &[UserEntry]) -> Result<String> {
    let mut doc: toml_edit::DocumentMut =
        original.parse().context("failed to parse existing TOML config")?;

    // Serialize the current user list as a fresh mini-document, then lift its
    // `users` item into the original document. This is the cleanest way to
    // produce a well-formatted `[[users]]` block via `toml_edit`'s serde
    // integration without hand-rolling the array-of-tables construction.
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        users: &'a [UserEntry],
    }
    let rendered = toml_edit::ser::to_string(&Wrapper { users })
        .context("failed to serialize users as TOML")?;
    let rendered_doc: toml_edit::DocumentMut =
        rendered.parse().context("toml_edit failed to re-parse generated users TOML")?;
    let users_item = rendered_doc
        .get("users")
        .cloned()
        .ok_or_else(|| anyhow!("serialized users had no `users` key"))?;

    doc.insert("users", users_item);
    Ok(doc.to_string())
}

#[cfg(test)]
#[path = "tests/persist.rs"]
mod tests;
