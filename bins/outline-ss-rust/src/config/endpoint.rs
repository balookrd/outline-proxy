//! The server's carrier-endpoint model. A single global list of
//! `{path, kind, padded}` records replaces the old per-user path fields and the
//! separate `[padding] paths` list. Endpoints are startup-only; users are pure
//! credentials that work on every endpoint of their kind.

use serde::{Deserialize, Serialize};

/// Carrier + transport shape of one endpoint. `snake_case` on the wire so the
/// TOML reads `kind = "ws_ss"`. The variant fixes both the carrier family
/// (WS vs XHTTP) and the Shadowsocks/VLESS shape; the HTTP version (h1/h2/h3)
/// is chosen by the listener, not the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// Combined SS-over-WS: one path carries both TCP and UDP legs.
    WsSs,
    /// Split SS-over-WS, TCP leg.
    WsSsTcp,
    /// Split SS-over-WS, UDP leg.
    WsSsUdp,
    /// VLESS-over-WS.
    WsVless,
    /// Combined SS-over-XHTTP: one base carries both legs.
    XhttpSs,
    /// Split SS-over-XHTTP, TCP leg.
    XhttpSsTcp,
    /// Split SS-over-XHTTP, UDP leg.
    XhttpSsUdp,
    /// VLESS-over-XHTTP.
    XhttpVless,
}

// The route builder starts calling these in Task 2; nothing does yet.
#[allow(dead_code)]
impl EndpointKind {
    /// True for every Shadowsocks kind (pool = SS `UserKey`s).
    pub fn is_ss(self) -> bool {
        !self.is_vless()
    }

    /// True for the two VLESS kinds (pool = `VlessUser`s).
    pub fn is_vless(self) -> bool {
        matches!(self, EndpointKind::WsVless | EndpointKind::XhttpVless)
    }

    /// A combined SS kind carries both legs on one path, so it populates two
    /// route maps and `bootstrap/axum.rs` registers a `<base>/{token}` upgrade.
    pub fn is_combined(self) -> bool {
        matches!(self, EndpointKind::WsSs | EndpointKind::XhttpSs)
    }
}

/// Resolved endpoint: the runtime form after config load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointConfig {
    pub path: String,
    pub kind: EndpointKind,
    pub padded: bool,
}

#[cfg(test)]
#[path = "tests/endpoint.rs"]
mod tests;
