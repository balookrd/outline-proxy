//! Shadowsocks crypto primitives live in the `shadowsocks-crypto` workspace
//! crate. This module is a thin facade so the rest of the binary can keep
//! using `crate::crypto::*` paths without churn.

pub use shadowsocks_crypto::*;
