use serde::{Deserialize, Serialize};
use thiserror::Error;

// Cipher selection is shared with the client side; the enum (serde names,
// clap value names, key/salt lengths, SS2022 classification) lives in
// `outline-wire`.
pub use outline_wire::CipherKind;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserEntry {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<CipherKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path_tcp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path_udp: Option<String>,
    /// Per-user override of the global `[websocket].ws_path_ss` — the
    /// combined SS-over-WS path (one path for both TCP and UDP legs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path_ss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_path_vless: Option<String>,
    /// Per-user override of the global `[websocket].xhttp_path_vless`
    /// base. Defaulting to the global keeps single-tenant configs
    /// terse; per-user overrides are useful for path-segregated
    /// deployments behind a CDN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_path_vless: Option<String>,
    /// Per-user override of the global `[websocket].xhttp_path_tcp` base.
    /// Same semantics as `xhttp_path_vless`, but selects the path under
    /// which this user is reachable over Shadowsocks-over-XHTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_path_tcp: Option<String>,
    /// Per-user override of the global `[websocket].xhttp_path_udp`
    /// base — the SS-UDP-over-XHTTP path (separate from the TCP path,
    /// mirroring `ws_path_tcp` vs `ws_path_udp`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_path_udp: Option<String>,
    /// Per-user override of the global `[websocket].xhttp_path_ss` — the
    /// combined SS-over-XHTTP path (one path for both TCP and UDP legs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_path_ss: Option<String>,
    /// `false` blocks the user without removing their config entry. Absent
    /// in the config means enabled; control-plane mutations write the field
    /// explicitly so on-disk state round-trips unambiguously.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl UserEntry {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn effective_method(&self, default: CipherKind) -> CipherKind {
        self.method.unwrap_or(default)
    }

    pub fn effective_ws_path_tcp<'a>(&'a self, default: &'a str) -> &'a str {
        self.ws_path_tcp.as_deref().unwrap_or(default)
    }

    pub fn effective_ws_path_udp<'a>(&'a self, default: &'a str) -> &'a str {
        self.ws_path_udp.as_deref().unwrap_or(default)
    }

    pub fn effective_ws_path_vless<'a>(&'a self, default: Option<&'a str>) -> Option<&'a str> {
        self.ws_path_vless.as_deref().or(default)
    }

    pub fn effective_xhttp_path_vless<'a>(&'a self, default: Option<&'a str>) -> Option<&'a str> {
        self.xhttp_path_vless.as_deref().or(default)
    }

    pub fn effective_xhttp_path_tcp<'a>(&'a self, default: Option<&'a str>) -> Option<&'a str> {
        self.xhttp_path_tcp.as_deref().or(default)
    }

    pub fn effective_xhttp_path_udp<'a>(&'a self, default: Option<&'a str>) -> Option<&'a str> {
        self.xhttp_path_udp.as_deref().or(default)
    }

    /// Combined SS-over-WS path for this user. An explicit per-user split path
    /// (`ws_path_tcp` / `ws_path_udp`) opts the user OUT of a global combined
    /// `ws_path_ss` — specific beats general, so a global combined default does
    /// not clash with users that pin their own split paths. A per-user
    /// `ws_path_ss` still wins over the global split defaults.
    pub fn effective_ws_path_ss<'a>(&'a self, default: Option<&'a str>) -> Option<&'a str> {
        if self.ws_path_tcp.is_some() || self.ws_path_udp.is_some() {
            return None;
        }
        self.ws_path_ss.as_deref().or(default)
    }

    /// Combined SS-over-XHTTP path for this user. Same per-user-split-wins rule
    /// as [`Self::effective_ws_path_ss`].
    pub fn effective_xhttp_path_ss<'a>(&'a self, default: Option<&'a str>) -> Option<&'a str> {
        if self.xhttp_path_tcp.is_some() || self.xhttp_path_udp.is_some() {
            return None;
        }
        self.xhttp_path_ss.as_deref().or(default)
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configure at least one key via password or [[users]] with password/vless_id")]
    MissingUsers,
    #[error("duplicate user id: {0}")]
    DuplicateUserId(String),
}
