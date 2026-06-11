//! Wire-protocol vocabulary, re-exported from the shared `outline-wire`
//! crate (one codec for both the server and the `outline-ws-rust` client).
//! Server-only protocol entities (e.g. [`vless::VlessUser`]) stay here.

pub mod vless;
pub mod vless_mux;

pub use outline_wire::target::{TargetAddr, parse_target_addr};
