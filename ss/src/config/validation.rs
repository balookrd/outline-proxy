use std::{
    collections::{BTreeSet, HashSet},
    path::PathBuf,
};

use anyhow::{Result, bail};

use super::{AccessKeyConfig, Config, H3Alpn};

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !self.data_plane_listener_enabled() {
            bail!("configure at least one data-plane listener: listen, h3_listen, or ss_listen");
        }
        Self::validate_cert_pair(&self.tls_cert_path, &self.tls_key_path, "tls")?;
        let h3_certs_present =
            Self::validate_cert_pair(&self.h3_cert_path, &self.h3_key_path, "h3")?;
        if h3_certs_present && self.h3_listen.is_none() {
            bail!("h3_listen must be configured explicitly when HTTP/3 is enabled");
        }
        if !h3_certs_present && self.h3_listen.is_some() {
            bail!("h3_listen requires both h3_cert_path and h3_key_path");
        }
        if !self.metrics_path.starts_with('/') {
            bail!("metrics_path must start with '/'");
        }
        if self.listen.is_some() && self.listen == self.ss_listen {
            bail!("ss_listen must differ from listen");
        }
        if self.ss_listen.is_some() && self.ss_listen == self.metrics_listen {
            bail!("ss_listen must differ from metrics_listen");
        }
        if self.ss_listen.is_some() && self.ss_listen == self.effective_h3_listen() {
            bail!("ss_listen must differ from h3_listen");
        }
        if self.listen.is_some() && self.listen == self.metrics_listen {
            bail!("listen must differ from metrics_listen");
        }
        if let Some(dashboard) = &self.dashboard {
            if self.listen.is_some_and(|listen| listen == dashboard.listen) {
                bail!("dashboard.listen must differ from listen");
            }
            if self.ss_listen.is_some_and(|listen| listen == dashboard.listen) {
                bail!("dashboard.listen must differ from ss_listen");
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
        let users = self.user_entries()?;
        let mut tcp_paths = BTreeSet::new();
        let mut udp_paths = BTreeSet::new();
        for user in users {
            if let Some(path) = user.ws_path_tcp.as_deref()
                && !path.starts_with('/')
            {
                bail!("user {} ws_path_tcp must start with '/'", user.id);
            }
            if let Some(path) = user.ws_path_udp.as_deref()
                && !path.starts_with('/')
            {
                bail!("user {} ws_path_udp must start with '/'", user.id);
            }
            tcp_paths.insert(user.effective_ws_path_tcp(&self.ws_path_tcp).to_owned());
            udp_paths.insert(user.effective_ws_path_udp(&self.ws_path_udp).to_owned());
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
            if user.vless_id.is_some() {
                let ws_path = user.effective_ws_path_vless(self.ws_path_vless.as_deref());
                let xhttp_path =
                    user.effective_xhttp_path_vless(self.xhttp_path_vless.as_deref());
                let has_raw_quic = self.h3_alpn.contains(&H3Alpn::Vless);
                if let Some(path) = ws_path {
                    vless_paths.insert(path.to_owned());
                }
                if ws_path.is_none() && xhttp_path.is_none() && !has_raw_quic {
                    bail!(
                        "user {} vless_id requires at least one transport: \
                         ws_path_vless, xhttp_path_vless, or raw VLESS-over-QUIC \
                         (\"vless\" in [server.h3].alpn)",
                        user.id
                    );
                }
            }
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
        if let Some(conflict) = tcp_paths.intersection(&udp_paths).next() {
            bail!("tcp and udp websocket paths must be distinct, conflict on {}", conflict);
        }
        if let Some(conflict) = tcp_paths.intersection(&vless_paths).next() {
            bail!("tcp and vless websocket paths must be distinct, conflict on {}", conflict);
        }
        if let Some(conflict) = udp_paths.intersection(&vless_paths).next() {
            bail!("udp and vless websocket paths must be distinct, conflict on {}", conflict);
        }
        let mut xhttp_paths = BTreeSet::new();
        if let Some(path) = self.xhttp_path_vless.as_deref()
            && !path.starts_with('/')
        {
            bail!("xhttp_path_vless must start with '/'");
        }
        if self.xhttp_path_vless.is_some()
            && self.users.iter().all(|user| user.vless_id.is_none())
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
        if self.http_root_auth
            && (tcp_paths.contains("/")
                || udp_paths.contains("/")
                || vless_paths.contains("/")
                || xhttp_paths.contains("/"))
        {
            bail!("http_root_auth requires all websocket paths to differ from '/'");
        }
        if self.http_root_realm.chars().any(char::is_control) {
            bail!("http_root_realm must not contain control characters");
        }
        if self.outbound_ipv6_prefix.is_some() && self.outbound_ipv6_interface.is_some() {
            bail!(
                "outbound_ipv6_prefix and outbound_ipv6_interface are mutually exclusive; \
                 pick one"
            );
        }
        if self.outbound_ipv6_interface.as_deref().is_some_and(str::is_empty) {
            bail!("outbound_ipv6_interface must not be empty");
        }
        if self.outbound_ipv6_refresh_secs == 0 {
            bail!("outbound_ipv6_refresh_secs must be > 0");
        }
        if self.http_fallback.is_some() && self.listen.is_none() {
            bail!("http_fallback requires the [server] listen to be configured");
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
