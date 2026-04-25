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
        if let Some(path) = self.vless_ws_path.as_deref()
            && !path.starts_with('/')
        {
            bail!("vless_ws_path must start with '/'");
        }
        if self.vless_ws_path.is_some() && self.users.iter().all(|user| user.vless_id.is_none()) {
            bail!("vless_ws_path requires at least one [[users]] entry with vless_id");
        }
        for user in &self.users {
            if let Some(path) = user.vless_ws_path.as_deref()
                && !path.starts_with('/')
            {
                bail!("user {} vless_ws_path must start with '/'", user.id);
            }
            if user.vless_ws_path.is_some() && user.vless_id.is_none() {
                bail!("user {} vless_ws_path requires vless_id", user.id);
            }
            if user.vless_id.is_some() {
                match user.effective_vless_ws_path(self.vless_ws_path.as_deref()) {
                    Some(path) => {
                        vless_paths.insert(path.to_owned());
                    },
                    None => {
                        // No WebSocket path is fine when raw VLESS-over-QUIC
                        // is enabled — the user is still reachable on the
                        // QUIC endpoint via ALPN "vless".
                        if !self.h3_alpn.contains(&H3Alpn::Vless) {
                            bail!(
                                "user {} vless_id requires vless_ws_path (or enable raw \
                                 VLESS-over-QUIC by adding \"vless\" to [server.h3].alpn)",
                                user.id
                            );
                        }
                    },
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
        if self.http_root_auth
            && (tcp_paths.contains("/") || udp_paths.contains("/") || vless_paths.contains("/"))
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
            config_path: None,
            control: None,
            dashboard: None,
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            h3_alpn: vec![crate::config::H3Alpn::H3],
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            vless_ws_path: None,
            http_root_auth: false,
            http_root_realm: default_http_root_realm(),
            users: vec![super::super::UserEntry {
                id: "default".into(),
                password: Some("secret".into()),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                vless_ws_path: None,
                enabled: None,
            }],
            method: CipherKind::Chacha20IetfPoly1305,
            access_key: Default::default(),
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
    fn allows_vless_only_users() {
        Config {
            vless_ws_path: Some("/vless".into()),
            users: vec![super::super::UserEntry {
                id: "550e8400-e29b-41d4-a716-446655440000".into(),
                password: None,
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                vless_ws_path: None,
                enabled: None,
            }],
            ..base_config()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn rejects_vless_path_conflict_with_tcp_path() {
        let error = Config {
            vless_ws_path: Some("/tcp".into()),
            users: vec![
                super::super::UserEntry {
                    id: "alice".into(),
                    password: Some("secret".into()),
                    fwmark: None,
                    method: None,
                    ws_path_tcp: None,
                    ws_path_udp: None,
                    vless_id: None,
                    vless_ws_path: None,
                    enabled: None,
                },
                super::super::UserEntry {
                    id: "550e8400-e29b-41d4-a716-446655440000".into(),
                    password: None,
                    fwmark: None,
                    method: None,
                    ws_path_tcp: None,
                    ws_path_udp: None,
                    vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                    vless_ws_path: None,
                    enabled: None,
                },
            ],
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("tcp and vless websocket paths must be distinct"));
    }

    #[test]
    fn allows_per_user_vless_path_without_global_default() {
        Config {
            vless_ws_path: None,
            users: vec![super::super::UserEntry {
                id: "alice".into(),
                password: None,
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                vless_ws_path: Some("/alice-vless".into()),
                enabled: None,
            }],
            ..base_config()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn allows_vless_id_without_path_when_raw_quic_alpn_enabled() {
        Config {
            vless_ws_path: None,
            h3_alpn: vec![crate::config::H3Alpn::H3, crate::config::H3Alpn::Vless],
            users: vec![super::super::UserEntry {
                id: "alice".into(),
                password: None,
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                vless_ws_path: None,
                enabled: None,
            }],
            ..base_config()
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn rejects_vless_id_without_any_path() {
        let error = Config {
            vless_ws_path: None,
            users: vec![super::super::UserEntry {
                id: "alice".into(),
                password: None,
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                vless_ws_path: None,
                enabled: None,
            }],
            ..base_config()
        }
        .validate()
        .unwrap_err()
        .to_string();

        assert!(error.contains("user alice vless_id requires vless_ws_path"));
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
