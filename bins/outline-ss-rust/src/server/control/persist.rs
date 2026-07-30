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

#[cfg(test)]
#[path = "tests/persist.rs"]
mod tests;
