//! SOCKS5 protocol primitives live in the `socks5-proto` workspace crate.
//! This module is a thin facade so the rest of the binary can keep using
//! `crate::socks5::*` paths without churn.

pub use socks5_proto::*;
