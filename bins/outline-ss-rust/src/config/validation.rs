use std::{
    collections::{BTreeSet, HashSet},
    path::PathBuf,
};

use anyhow::{Result, bail};

use super::{AccessKeyConfig, Config};

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
        if let Some(dashboard) = &self.dashboard {
            if self.listen.is_some_and(|listen| listen == dashboard.listen) {
                bail!("dashboard.listen must differ from listen");
            }
            if self.metrics_listen.is_some_and(|listen| listen == dashboard.listen) {
                bail!("dashboard.listen must differ from metrics_listen");
            }
            if self
                .effective_h3_listen()
                .is_some_and(|listen| listen == dashboard.listen)
            {
                bail!("dashboard.listen must differ from h3_listen");
            }
        }
        if self.padding.enabled && self.padding.paths.is_empty() {
            bail!(
                "[padding] enabled requires a non-empty `paths` list — the carrier paths to \
                 pad; third-party clients on other paths stay on the plain wire"
            );
        }
        let users = self.user_entries()?;
        let mut tcp_paths = BTreeSet::new();
        let mut udp_paths = BTreeSet::new();
        // Combined-path users put BOTH legs on one base path via `ws_path_ss`
        // (the server splits tcp/udp by the hidden `/{token}` bit). They go in
        // their own `ws_ss_paths` set; split users use the distinct
        // `ws_path_tcp` / `ws_path_udp`. Every category must stay distinct.
        let mut ws_ss_paths = BTreeSet::new();
        for user in users {
            for (path, field) in [
                (user.ws_path_tcp.as_deref(), "ws_path_tcp"),
                (user.ws_path_udp.as_deref(), "ws_path_udp"),
                (user.ws_path_ss.as_deref(), "ws_path_ss"),
            ] {
                if let Some(path) = path
                    && !path.starts_with('/')
                {
                    bail!("user {} {field} must start with '/'", user.id);
                }
            }
            // A user must not pin BOTH a per-user combined `ws_path_ss` and a
            // per-user split path. (A *global* combined `ws_path_ss` does not
            // clash: a user's own split paths opt it out — see
            // `effective_ws_path_ss`.)
            if user.ws_path_ss.is_some()
                && (user.ws_path_tcp.is_some() || user.ws_path_udp.is_some())
            {
                bail!(
                    "user {} sets both a per-user `ws_path_ss` (combined) and \
                     `ws_path_tcp` / `ws_path_udp` (split) — pick one",
                    user.id
                );
            }
            match user.effective_ws_path_ss(self.ws_path_ss.as_deref()) {
                Some(ss) => {
                    ws_ss_paths.insert(ss.to_owned());
                },
                None => {
                    tcp_paths.insert(user.effective_ws_path_tcp(&self.ws_path_tcp).to_owned());
                    udp_paths.insert(user.effective_ws_path_udp(&self.ws_path_udp).to_owned());
                },
            }
        }
        let mut vless_paths = BTreeSet::new();
        let vless_enabled_users = self.users.iter().filter(|user| user.vless_id.is_some());
        if let Some(path) = self.ws_path_vless.as_deref()
            && !path.starts_with('/')
        {
            bail!("ws_path_vless must start with '/'");
        }
        if self.ws_path_vless.is_some() && self.users.iter().all(|user| user.vless_id.is_none()) {
            bail!("ws_path_vless requires at least one [[users]] entry with vless_id");
        }
        for user in &self.users {
            if let Some(path) = user.ws_path_vless.as_deref()
                && !path.starts_with('/')
            {
                bail!("user {} ws_path_vless must start with '/'", user.id);
            }
            if user.ws_path_vless.is_some() && user.vless_id.is_none() {
                bail!("user {} ws_path_vless requires vless_id", user.id);
            }
            if user.vless_id.is_some()
                && let Some(path) = user.effective_ws_path_vless(self.ws_path_vless.as_deref())
            {
                vless_paths.insert(path.to_owned());
            }
            // A vless_id user with neither ws_path_vless nor xhttp_path_vless
            // has no forward transport now that raw VLESS-over-QUIC is gone.
            // That is not a hard error: the user is warned about and skipped
            // when the route maps are built (see `services::build`).
        }
        let mut vless_seen = HashSet::new();
        for user in vless_enabled_users {
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
        // Split tcp/udp must be distinct — a path carrying both legs uses the
        // combined `ws_path_ss` instead (tracked in `ws_ss_paths`).
        if let Some(conflict) = tcp_paths.intersection(&udp_paths).next() {
            bail!(
                "tcp and udp websocket paths must be distinct — to carry both legs on one \
                 path use a combined `ws_path_ss` instead, conflict on {}",
                conflict,
            );
        }
        if let Some(conflict) = tcp_paths.intersection(&vless_paths).next() {
            bail!("tcp and vless websocket paths must be distinct, conflict on {}", conflict);
        }
        if let Some(conflict) = udp_paths.intersection(&vless_paths).next() {
            bail!("udp and vless websocket paths must be distinct, conflict on {}", conflict);
        }
        // The combined ws path must not collide with any split or vless path.
        for (other, label) in [(&tcp_paths, "tcp"), (&udp_paths, "udp"), (&vless_paths, "vless")] {
            if let Some(conflict) = ws_ss_paths.intersection(other).next() {
                bail!(
                    "combined ws_path_ss must differ from the {label} websocket path, conflict on {}",
                    conflict,
                );
            }
        }
        let mut xhttp_paths = BTreeSet::new();
        if let Some(path) = self.xhttp_path_vless.as_deref()
            && !path.starts_with('/')
        {
            bail!("xhttp_path_vless must start with '/'");
        }
        if self.xhttp_path_vless.is_some() && self.users.iter().all(|user| user.vless_id.is_none())
        {
            bail!("xhttp_path_vless requires at least one [[users]] entry with vless_id");
        }
        for user in &self.users {
            if let Some(path) = user.xhttp_path_vless.as_deref()
                && !path.starts_with('/')
            {
                bail!("user {} xhttp_path_vless must start with '/'", user.id);
            }
            if user.xhttp_path_vless.is_some() && user.vless_id.is_none() {
                bail!("user {} xhttp_path_vless requires vless_id", user.id);
            }
            if user.vless_id.is_some()
                && let Some(path) =
                    user.effective_xhttp_path_vless(self.xhttp_path_vless.as_deref())
            {
                xhttp_paths.insert(path.to_owned());
            }
        }
        if let Some(conflict) = tcp_paths.intersection(&xhttp_paths).next() {
            bail!("tcp and xhttp paths must be distinct, conflict on {}", conflict);
        }
        if let Some(conflict) = udp_paths.intersection(&xhttp_paths).next() {
            bail!("udp and xhttp paths must be distinct, conflict on {}", conflict);
        }
        if let Some(conflict) = vless_paths.intersection(&xhttp_paths).next() {
            bail!(
                "vless ws and xhttp paths must be distinct (xhttp adds an `/{{id}}` suffix), \
                 conflict on {}",
                conflict,
            );
        }
        // ── SS-over-XHTTP paths ──────────────────────────────────────────
        // SS identity is a password (not a vless_id). Three categories: split
        // tcp (`xhttp_path_tcp`), split udp (`xhttp_path_udp`), and combined
        // (`xhttp_path_ss`, both legs on one base path split by the session-id
        // bit). One base path serves one protocol, so all stay distinct.
        let no_password = self.users.iter().all(|user| user.password.is_none());
        for (global, field) in [
            (self.xhttp_path_tcp.as_deref(), "xhttp_path_tcp"),
            (self.xhttp_path_udp.as_deref(), "xhttp_path_udp"),
            (self.xhttp_path_ss.as_deref(), "xhttp_path_ss"),
        ] {
            if let Some(path) = global {
                if !path.starts_with('/') {
                    bail!("{field} must start with '/'");
                }
                if no_password {
                    bail!("{field} requires at least one [[users]] entry with a password");
                }
            }
        }
        let mut ss_xhttp_tcp_paths = BTreeSet::new();
        let mut ss_xhttp_udp_paths = BTreeSet::new();
        let mut ss_xhttp_combined_paths = BTreeSet::new();
        for user in &self.users {
            for (path, field) in [
                (user.xhttp_path_tcp.as_deref(), "xhttp_path_tcp"),
                (user.xhttp_path_udp.as_deref(), "xhttp_path_udp"),
                (user.xhttp_path_ss.as_deref(), "xhttp_path_ss"),
            ] {
                if let Some(path) = path {
                    if !path.starts_with('/') {
                        bail!("user {} {field} must start with '/'", user.id);
                    }
                    if user.password.is_none() {
                        bail!("user {} {field} requires a password", user.id);
                    }
                }
            }
            if user.password.is_none() {
                continue;
            }
            // A user must not pin BOTH a per-user combined `xhttp_path_ss` and
            // a per-user split path. (A *global* combined does not clash — a
            // user's own split paths opt it out, see `effective_xhttp_path_ss`.)
            if user.xhttp_path_ss.is_some()
                && (user.xhttp_path_tcp.is_some() || user.xhttp_path_udp.is_some())
            {
                bail!(
                    "user {} sets both a per-user `xhttp_path_ss` (combined) and \
                     `xhttp_path_tcp` / `xhttp_path_udp` (split) — pick one",
                    user.id
                );
            }
            match user.effective_xhttp_path_ss(self.xhttp_path_ss.as_deref()) {
                Some(ss) => {
                    ss_xhttp_combined_paths.insert(ss.to_owned());
                },
                None => {
                    if let Some(p) = user.effective_xhttp_path_tcp(self.xhttp_path_tcp.as_deref()) {
                        ss_xhttp_tcp_paths.insert(p.to_owned());
                    }
                    if let Some(p) = user.effective_xhttp_path_udp(self.xhttp_path_udp.as_deref()) {
                        ss_xhttp_udp_paths.insert(p.to_owned());
                    }
                },
            }
        }
        // ss-xhttp split tcp vs udp must differ (combined uses `xhttp_path_ss`).
        if let Some(c) = ss_xhttp_tcp_paths.intersection(&ss_xhttp_udp_paths).next() {
            bail!(
                "ss-xhttp tcp and udp paths must be distinct — use a combined `xhttp_path_ss` \
                 to carry both on one path, conflict on {}",
                c,
            );
        }
        // Every ss-xhttp category is distinct from vless-xhttp and the WS paths
        // (one base path serves one protocol).
        for (set, label) in [
            (&ss_xhttp_tcp_paths, "ss-xhttp tcp"),
            (&ss_xhttp_udp_paths, "ss-xhttp udp"),
            (&ss_xhttp_combined_paths, "ss-xhttp combined"),
        ] {
            for (other, olabel) in [
                (&xhttp_paths, "vless-xhttp"),
                (&tcp_paths, "ws-tcp"),
                (&udp_paths, "ws-udp"),
                (&vless_paths, "vless-ws"),
                (&ws_ss_paths, "ws-combined"),
            ] {
                if let Some(c) = set.intersection(other).next() {
                    bail!("{label} and {olabel} base paths must be distinct, conflict on {}", c);
                }
            }
        }
        // Combined ss-xhttp must not collide with split ss-xhttp either.
        for (other, olabel) in [(&ss_xhttp_tcp_paths, "tcp"), (&ss_xhttp_udp_paths, "udp")] {
            if let Some(c) = ss_xhttp_combined_paths.intersection(other).next() {
                bail!(
                    "combined `xhttp_path_ss` must differ from the split ss-xhttp {olabel} path, \
                     conflict on {}",
                    c,
                );
            }
        }
        if self.http_root_auth
            && (tcp_paths.contains("/")
                || udp_paths.contains("/")
                || ws_ss_paths.contains("/")
                || vless_paths.contains("/")
                || xhttp_paths.contains("/")
                || ss_xhttp_tcp_paths.contains("/")
                || ss_xhttp_udp_paths.contains("/")
                || ss_xhttp_combined_paths.contains("/"))
        {
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
        self.tuning.validate()?;
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

impl AccessKeyConfig {
    pub(super) fn validate(&self) -> Result<()> {
        if !matches!(self.public_scheme.as_str(), "ws" | "wss") {
            bail!("public_scheme must be either \"ws\" or \"wss\"");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/validation.rs"]
mod tests;
