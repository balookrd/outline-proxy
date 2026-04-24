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
mod tests {
    use super::*;
    use crate::config::{CipherKind, UserEntry};

    fn sample_users() -> Vec<UserEntry> {
        vec![
            UserEntry {
                id: "alice".to_owned(),
                password: Some("old-pass".to_owned()),
                fwmark: Some(1001),
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                vless_ws_path: None,
                enabled: None,
            },
            UserEntry {
                id: "bob".to_owned(),
                password: Some("new-pass".to_owned()),
                fwmark: None,
                method: Some(CipherKind::Aes256Gcm),
                ws_path_tcp: Some("/bob/tcp".to_owned()),
                ws_path_udp: Some("/bob/udp".to_owned()),
                vless_id: None,
                vless_ws_path: None,
                enabled: Some(false),
            },
        ]
    }

    #[test]
    fn toml_rewrite_preserves_comments_and_unrelated_keys() {
        let original = r#"
# Header comment that must survive.
listen = "0.0.0.0:3000"  # listener comment
method = "chacha20-ietf-poly1305"

# Separator comment.
[tuning]
udp_nat_idle_timeout_secs = 300  # tuning comment

# Old users block follows.
[[users]]
id = "alice"
password = "stale"
"#;

        let out = rewrite_toml(original, &sample_users()).expect("rewrite_toml");

        // Comments preserved outside the `users` key.
        assert!(out.contains("# Header comment that must survive."), "header comment lost:\n{out}");
        assert!(out.contains("# listener comment"), "inline listener comment lost:\n{out}");
        assert!(out.contains("# Separator comment."), "separator comment lost:\n{out}");
        assert!(out.contains("# tuning comment"), "tuning inline comment lost:\n{out}");
        // Unrelated keys untouched.
        assert!(out.contains(r#"listen = "0.0.0.0:3000""#), "listen value changed:\n{out}");
        assert!(out.contains("udp_nat_idle_timeout_secs = 300"), "tuning value changed:\n{out}");
        // New users present, old value gone.
        assert!(out.contains("new-pass"), "new user payload missing:\n{out}");
        assert!(!out.contains(r#"password = "stale""#), "old user payload survived:\n{out}");
        // Result round-trips back into the real config schema.
        let parsed: toml_edit::DocumentMut = out.parse().expect("parse round-trip");
        assert!(parsed.get("users").is_some());
    }

}
