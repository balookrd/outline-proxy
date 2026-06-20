use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use anyhow::bail;
use outline_net::{IpAliasError, IpAliasTable};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Cipher selection is shared with the client side; the enum (serde names,
// clap value names, key/salt lengths, SS2022 classification) lives in
// `outline-wire`.
pub use outline_wire::CipherKind;

/// Value of one entry in `[users.aliases]`: a single CIDR/IP string or a list
/// of them. Accepting both shapes keeps single-subnet configs terse
/// (`alias = "10.0.0.0/8"`) while allowing several (`alias = ["a", "b"]`). The
/// original shape is preserved on serialize, so the config round-trips stably.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrManyCidr {
    One(String),
    Many(Vec<String>),
}

impl OneOrManyCidr {
    /// The configured CIDR/IP strings as a slice, regardless of shape.
    pub fn as_slice(&self) -> &[String] {
        match self {
            Self::One(s) => std::slice::from_ref(s),
            Self::Many(v) => v.as_slice(),
        }
    }
}

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
    /// Source-IP → alias map for per-identity ACCOUNTING ONLY. After normal
    /// authentication, if the client's source IP falls into one of these
    /// subnets the effective metrics/NAT/log label becomes the matching alias;
    /// otherwise it stays [`Self::id`]. Never affects authentication, keys, or
    /// access control. Behind a CDN the peer is the CDN's IP, so aliasing only
    /// applies on direct connections — see README.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aliases: Option<BTreeMap<String, OneOrManyCidr>>,
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

    /// Build this user's runtime source-IP alias table. `Ok(None)` when no
    /// aliases are configured (or they resolve to an empty set). The returned
    /// `Arc` is shared by every runtime user derived from this entry (one entry
    /// can feed several route tables). Errors on malformed CIDRs / empty alias
    /// names so both startup and the control plane reject bad config the same
    /// way.
    pub fn build_ip_aliases(&self) -> Result<Option<Arc<IpAliasTable>>, IpAliasError> {
        let Some(map) = &self.aliases else {
            return Ok(None);
        };
        let table = IpAliasTable::build(map.iter().map(|(k, v)| (k.as_str(), v.as_slice())))?;
        Ok((!table.is_empty()).then(|| Arc::new(table)))
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configure at least one key via password or [[users]] with password/vless_id")]
    MissingUsers,
    #[error("duplicate user id: {0}")]
    DuplicateUserId(String),
}

/// Validate per-user IP aliases across a whole user set. Shared by startup
/// config validation ([`super::Config::validate`]) and the control plane
/// ([`crate::server::control`]) so both reject identical configs:
///
/// - every alias's CIDR/IP strings parse and alias names are non-empty
///   (delegated to [`IpAliasTable::build`] via [`UserEntry::build_ip_aliases`]);
/// - alias names are globally unique and never collide with any user id —
///   otherwise two identities would silently share one accounting label,
///   cross-attributing traffic.
pub fn validate_ip_aliases<'a>(
    users: impl IntoIterator<Item = &'a UserEntry>,
) -> anyhow::Result<()> {
    let users: Vec<&UserEntry> = users.into_iter().collect();
    // The accounting-label namespace is every user id plus every alias name.
    let mut names: HashSet<&str> = users.iter().map(|u| u.id.as_str()).collect();
    for user in &users {
        let Some(map) = &user.aliases else { continue };
        // Parse/validate CIDRs (also rejects empty alias names and
        // ambiguous duplicate prefixes).
        user.build_ip_aliases()
            .map_err(|e| anyhow::anyhow!("user {}: {e}", user.id))?;
        for alias in map.keys() {
            if !names.insert(alias.as_str()) {
                bail!(
                    "user {}: alias {alias:?} collides with another user id or alias \
                     (accounting labels must be unique)",
                    user.id
                );
            }
        }
    }
    Ok(())
}
