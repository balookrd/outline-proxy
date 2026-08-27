use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use anyhow::{Result, bail};

use super::{Config, EndpointKind};
use crate::server::MAX_USER_LEN;

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !self.data_plane_listener_enabled() {
            bail!("configure at least one data-plane listener: listen or h3_listen");
        }
        Self::validate_cert_pair(&self.tls_cert_path, &self.tls_key_path, "tls")?;
        Self::validate_cert_pair(&self.h3_cert_path, &self.h3_key_path, "h3")?;
        Self::validate_cert_array(&self.tls_certs, "server.certs")?;
        Self::validate_cert_array(&self.h3_certs, "server.h3.certs")?;
        let h3_active = self.h3_enabled();
        if h3_active && self.h3_listen.is_none() {
            bail!("h3_listen must be configured explicitly when HTTP/3 is enabled");
        }
        if !h3_active && self.h3_listen.is_some() {
            bail!(
                "h3_listen requires either an h3 cert/key pair (h3_cert_path + \
                 h3_key_path, optionally inherited from [server]) or at least one \
                 [[server.h3.certs]] entry"
            );
        }
        if !self.metrics_path.starts_with('/') {
            bail!("metrics_path must start with '/'");
        }
        if self.listen.is_some() && self.listen == self.metrics_listen {
            bail!("listen must differ from metrics_listen");
        }
        // Every vless_id must be a well-formed, globally unique UUID —
        // independent of which (if any) endpoint serves it.
        let mut vless_seen = HashSet::new();
        for user in self.users.iter().filter(|user| user.vless_id.is_some()) {
            let vless_id = user.vless_id.as_deref().expect("filtered above");
            let parsed = crate::protocol::vless::parse_uuid(vless_id)
                .map_err(|_| anyhow::anyhow!("invalid vless_id for user {}", user.id))?;
            if !vless_seen.insert(parsed) {
                bail!("duplicate vless_id for user {}", user.id);
            }
        }
        // Per-user source-IP aliases (accounting relabeling): every alias's
        // CIDRs must parse and alias names must be globally unique vs ids.
        super::validate_ip_aliases(&self.users)?;

        // ── Carrier endpoints ────────────────────────────────────────────
        // `self.endpoints` is the single source of truth for every carrier
        // path now (users are pure credentials that work on every endpoint of
        // their kind — see `config::endpoint`). axum/h3 register one handler
        // per literal path, so no two endpoints may ever share a path,
        // regardless of kind: a combined kind (`ws_ss` / `xhttp_ss`)
        // legitimately reuses *its own* path for both legs of one protocol
        // (that is the point of "combined"), but two different endpoint
        // entries claiming the same path is always a conflict — the same
        // invariant the old per-category `tcp`/`udp`/`vless`/`xhttp_*` path
        // sets enforced pairwise. One map from path to the kind that claimed
        // it catches every such conflict in a single pass.
        let has_password_user = self.users.iter().any(|user| user.password.is_some());
        let has_vless_user = self.users.iter().any(|user| user.vless_id.is_some());
        let mut claimed_paths: HashMap<String, EndpointKind> = HashMap::new();
        for ep in &self.endpoints {
            if !ep.path.starts_with('/') {
                bail!("endpoint path {:?} must start with '/'", ep.path);
            }
            if let Some(prev_kind) = claimed_paths.insert(ep.path.clone(), ep.kind) {
                let path = &ep.path;
                let kind = ep.kind;
                bail!(
                    "duplicate endpoint path {path:?}: claimed by both a {prev_kind:?} and a \
                     {kind:?} endpoint — every [[endpoint]] must use a distinct path"
                );
            }
            // An endpoint whose kind has no matching user pool is silently
            // unreachable, not a config error — the mirror-image warning
            // (users of a kind with no matching endpoint) lives in
            // `services::build`.
            if ep.kind.is_ss() && !has_password_user {
                tracing::warn!(
                    path = %ep.path,
                    "endpoint is a Shadowsocks kind but no [[users]] entry has a password; \
                     it will accept no one"
                );
            }
            if ep.kind.is_vless() && !has_vless_user {
                tracing::warn!(
                    path = %ep.path,
                    "endpoint is a VLESS kind but no [[users]] entry has vless_id; it will \
                     accept no one"
                );
            }
        }
        if self.http_root_auth && claimed_paths.contains_key("/") {
            bail!("http_root_auth requires all websocket paths to differ from '/'");
        }
        if self.http_root_realm.chars().any(char::is_control) {
            bail!("http_root_realm must not contain control characters");
        }
        let v6_source_modes = [
            self.outbound_ipv6_prefix.is_some(),
            self.outbound_ipv6_interface.is_some(),
            self.outbound_ipv6_prefix_interface.is_some(),
        ]
        .into_iter()
        .filter(|&set| set)
        .count();
        if v6_source_modes > 1 {
            bail!(
                "outbound_ipv6_prefix, outbound_ipv6_interface and \
                 outbound_ipv6_prefix_interface are mutually exclusive; pick one"
            );
        }
        if self.outbound_ipv6_interface.as_deref().is_some_and(str::is_empty) {
            bail!("outbound_ipv6_interface must not be empty");
        }
        if self
            .outbound_ipv6_prefix_interface
            .as_deref()
            .is_some_and(str::is_empty)
        {
            bail!("outbound_ipv6_prefix_interface must not be empty");
        }
        if self.outbound_ipv6_refresh_secs == 0 {
            bail!("outbound_ipv6_refresh_secs must be > 0");
        }
        // `outbound_ipv6_sticky` defaults to true and is a harmless no-op
        // without an IPv6 source (the cache is only built when a prefix /
        // interface is configured), so it is intentionally not an error to
        // leave it on with no source.
        if self.outbound_ipv6_sticky && self.outbound_ipv6_sticky_ttl_secs == 0 {
            bail!("outbound_ipv6_sticky_ttl_secs must be > 0 when outbound_ipv6_sticky is set");
        }
        if let Some(fb) = self.http_fallback.as_ref() {
            if fb.apply_to_h1 && self.listen.is_none() {
                bail!(
                    "http_fallback.apply_to_h1 = true requires the [server] listen to be configured",
                );
            }
            if fb.apply_to_h3 && self.h3_listen.is_none() {
                bail!(
                    "http_fallback.apply_to_h3 = true requires [server.h3] listen to be configured",
                );
            }
        }
        if self.sni_fallback.is_some() {
            if self.listen.is_none() {
                bail!("sni_fallback requires the [server] listen to be configured");
            }
            if !self.tcp_tls_enabled() {
                bail!(
                    "sni_fallback requires built-in TLS: set [server].cert_path / \
                     [server].key_path or at least one [[server.certs]] entry"
                );
            }
        }
        self.validate_cluster_user_names()?;
        self.tuning.validate()?;
        Ok(())
    }

    /// The one thing a cluster still needs its nodes to agree on: user *names*.
    ///
    /// Paths and per-user credentials are per-node — the edge terminates the
    /// client's crypto and the home resolves nothing about a relayed session
    /// (see `docs/CLUSTER-DEPLOY.md` §3a). What crosses the mesh is the name the
    /// edge attests in a `UserFrame`, which the home matches against the park's
    /// owner in `take_for_resume(id, user)`. A name that is empty, or longer
    /// than the frame's [`MAX_USER_LEN`] bound, could never authenticate a
    /// relayed session: the edge refuses to send it and the home's parser
    /// refuses to read it. Failing at load beats discovering it at the first
    /// relay, where the symptom is a silently lost resume.
    ///
    /// Every name that can reach a `UserFrame` is checked, which is more than
    /// the `[[users]]` ids: the attested name is the *effective accounting
    /// label*, so a `[users.aliases]` key becomes the name on the wire whenever
    /// the peer falls inside that alias's subnet (`UserKey::effective_label`,
    /// `VlessUser::with_effective_label`). Checking only the base ids would let
    /// exactly the failure this exists to prevent through, on the connections
    /// that happen to match a subnet.
    ///
    /// Only a clustered server is held to this. `Config::cluster` is the
    /// *resolved* section, which `resolve_cluster` leaves `None` unless
    /// `[cluster] enabled = true`, so a node with the section present but
    /// switched off is treated as standalone — it sends no `UserFrame` at all,
    /// its names are its own business, and existing single-node deployments keep
    /// loading unchanged.
    fn validate_cluster_user_names(&self) -> Result<()> {
        if self.cluster.is_none() {
            return Ok(());
        }
        for user in &self.users {
            Self::validate_cluster_user_name(&user.id, "[[users]] id")?;
            for alias in user.aliases.iter().flat_map(|map| map.keys()) {
                Self::validate_cluster_user_name(alias, "[users.aliases] name")?;
            }
        }
        Ok(())
    }

    /// One name the mesh may have to attest. `what` names the config key it came
    /// from so the operator knows which one to fix.
    fn validate_cluster_user_name(name: &str, what: &str) -> Result<()> {
        if name.is_empty() {
            bail!(
                "[cluster] is enabled, so every {what} must be a user name the mesh can attest: \
                 an empty user name can never authenticate a relayed session"
            );
        }
        if name.len() > MAX_USER_LEN {
            bail!(
                "[cluster] is enabled, so every {what} must fit the {MAX_USER_LEN}-byte mesh user \
                 name bound; {name:?} is {} bytes and can never authenticate a relayed session",
                name.len(),
            );
        }
        Ok(())
    }

    fn validate_cert_pair(
        cert: &Option<PathBuf>,
        key: &Option<PathBuf>,
        prefix: &str,
    ) -> Result<bool> {
        match (cert, key) {
            (Some(_), Some(_)) => Ok(true),
            (None, None) => Ok(false),
            _ => bail!("{prefix}_cert_path and {prefix}_key_path must be configured together"),
        }
    }

    fn validate_cert_array(entries: &[super::TlsCertEntry], label: &str) -> Result<()> {
        let mut seen = HashSet::new();
        for (idx, entry) in entries.iter().enumerate() {
            for sni in &entry.sni {
                if !seen.insert(sni.clone()) {
                    bail!("{label}[{idx}].sni {sni:?} is already claimed by an earlier entry");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/validation.rs"]
mod tests;
