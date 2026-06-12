//! Shared wire-protocol primitives for the Outline server/client pair.
//!
//! Both `outline-ss-rust` (server) and `outline-ws-rust` (client) speak the
//! same Shadowsocks AEAD / SS2022 / VLESS wire formats. This crate owns the
//! format-level vocabulary — cipher identifiers, target addresses, header
//! layouts, protocol constants — as pure parsing/encoding logic with no
//! async runtime and no AEAD backend. AEAD sealing/opening stays on each
//! side (`ring` on the server, RustCrypto on the client); the only crypto
//! hosted here is the backend-neutral key material both sides must derive
//! identically (EVP_BytesToKey, the BLAKE3 SS2022 session subkey). Functions
//! operate on plaintext bytes and take the current time as a parameter so
//! callers control the clock source.

pub mod cipher;
pub mod resume;
pub mod ss2022;
pub mod target;
pub mod vless;
pub mod vless_mux;
pub mod xhttp;

pub use cipher::{
    CipherKind, MasterKeyError, SS_SUBKEY_INFO, UnknownCipherError, evp_bytes_to_key,
};
pub use target::{TargetAddr, TargetAddrError, parse_target_addr, socket_addr_to_target};
