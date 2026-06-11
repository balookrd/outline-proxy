//! Shared helpers for the per-submodule test files in this directory.
//!
//! The actual tests live next to each crypto submodule's source file via
//! `#[path = "tests/<name>.rs"] mod tests;` — see `crypto/primitives.rs`,
//! `crypto/stream.rs`, etc. This `mod.rs` only exposes helpers that several
//! of those test files share.

use std::sync::Arc;

use super::UserKey;
use crate::config::CipherKind;

pub(super) fn users(cipher: CipherKind, password_a: &str, password_b: &str) -> Arc<[UserKey]> {
    Arc::from(
        vec![
            UserKey::new("alice", password_a, Some(1001), cipher).unwrap(),
            UserKey::new("bob", password_b, Some(1002), cipher).unwrap(),
        ]
        .into_boxed_slice(),
    )
}
