use std::{collections::BTreeSet, path::PathBuf};

use anyhow::{Result, bail};

use super::{AccessKeyConfig, Config};

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
        if let Some(conflict) = tcp_paths.intersection(&udp_paths).next() {
            bail!("tcp and udp websocket paths must be distinct, conflict on {}", conflict);
        }
        if self.http_root_auth && (tcp_paths.contains("/") || udp_paths.contains("/")) {
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
mod tests {
    use super::super::{CipherKind, Config, default_http_root_realm};

    fn base_config() -> Config {
        Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: default_http_root_realm(),
            password: Some("secret".into()),
            fwmark: None,
            users: vec![],
            method: CipherKind::Chacha20IetfPoly1305,
            tuning: super::super::TuningProfile::LARGE,
        }
    }

    #[test]
    fn requires_at_least_one_data_plane_listener() {
        let error = Config {
            listen: None,
            metrics_listen: Some("127.0.0.1:9090".parse().unwrap()),
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("configure at least one data-plane listener"));
    }

    #[test]
    fn requires_explicit_h3_listener_when_enabled() {
        let error = Config {
            listen: None,
            h3_cert_path: Some("cert.pem".into()),
            h3_key_path: Some("key.pem".into()),
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("h3_listen must be configured explicitly"));
    }

    #[test]
    fn allows_h3_listener_to_share_address_with_tcp_listener() {
        Config {
            h3_listen: Some("127.0.0.1:3000".parse().unwrap()),
            h3_cert_path: Some("cert.pem".into()),
            h3_key_path: Some("key.pem".into()),
            ..base_config()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn rejects_http_root_auth_on_root_ws_path() {
        let error = Config {
            ws_path_tcp: "/".into(),
            http_root_auth: true,
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("http_root_auth requires all websocket paths to differ from '/'"));
    }

    #[test]
    fn tuning_rejects_stream_window_above_connection_window() {
        let mut tuning = super::super::TuningProfile::LARGE;
        tuning.h3_stream_window_bytes = tuning.h3_connection_window_bytes + 1;
        let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
        assert!(error.contains("h3_stream_window_bytes"));
        assert!(error.contains("must not exceed"));
    }

    #[test]
    fn tuning_rejects_zero_values() {
        let mut tuning = super::super::TuningProfile::LARGE;
        tuning.h3_udp_socket_buffer_bytes = 0;
        let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
        assert!(error.contains("h3_udp_socket_buffer_bytes"));
    }

    #[test]
    fn tuning_rejects_oversized_h3_windows() {
        let mut tuning = super::super::TuningProfile::LARGE;
        tuning.h3_connection_window_bytes = (u32::MAX as u64) + 1;
        let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
        assert!(error.contains("h3_connection_window_bytes"));
    }

    #[test]
    fn rejects_http_root_realm_with_control_characters() {
        let error = Config {
            http_root_auth: true,
            http_root_realm: "bad\nrealm".into(),
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("http_root_realm must not contain control characters"));
    }
}
