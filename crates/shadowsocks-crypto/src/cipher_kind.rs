//! Cipher selection shared with the server side via `outline-wire`.
//!
//! Re-exported so existing `shadowsocks_crypto::CipherKind` imports keep
//! working; the enum (serde names, legacy aliases, `FromStr`/`Display`)
//! lives in the shared crate.

pub use outline_wire::CipherKind;
