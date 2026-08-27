use super::super::loader::parse;
use super::super::{
    CipherKind, Config, EndpointConfig, EndpointKind, OneOrManyCidr, default_http_root_realm,
};

fn aliases(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, OneOrManyCidr> {
    pairs
        .iter()
        .map(|(name, cidr)| (name.to_string(), OneOrManyCidr::One(cidr.to_string())))
        .collect()
}

/// One endpoint at `path`, unpadded. `kind` picks the carrier/protocol shape.
fn ep(path: &str, kind: EndpointKind) -> EndpointConfig {
    EndpointConfig { path: path.into(), kind, padded: false }
}

fn base_config() -> Config {
    Config {
        config_path: None,
        control: None,
        listen: Some("127.0.0.1:3000".parse().unwrap()),
        tls_cert_path: None,
        tls_key_path: None,
        tls_certs: Vec::new(),
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_certs: Vec::new(),
        h3_alpn: vec![crate::config::H3Alpn::H3],
        h3_initial_mtu: None,
        metrics_listen: None,
        metrics_path: "/metrics".into(),
        prefer_ipv4_upstream: false,
        outbound_ipv6_prefix: None,
        outbound_ipv6_interface: None,
        outbound_ipv6_prefix_interface: None,
        outbound_ipv6_refresh_secs: 30,
        outbound_ipv6_sticky: false,
        outbound_ipv6_sticky_ttl_secs: 1800,
        http_root_auth: false,
        http_root_realm: default_http_root_realm(),
        users: vec![super::super::UserEntry {
            id: "default".into(),
            password: Some("secret".into()),
            fwmark: None,
            method: None,
            vless_id: None,
            enabled: None,
            aliases: None,
        }],
        method: CipherKind::Chacha20IetfPoly1305,
        tuning: super::super::TuningProfile::LARGE,
        session_resumption: Default::default(),
        padding: Default::default(),
        http_fallback: None,
        sni_fallback: None,
        cluster: None,
        endpoints: Vec::new(),
    }
}

#[test]
fn padding_with_padded_paths_validates() {
    let mut cfg = base_config();
    cfg.padding.padded_paths = vec!["/tcp".to_owned()];
    cfg.validate().expect("a non-empty padded_paths list should validate");
}

#[test]
fn padding_scheme_resolves_for_padded_endpoints_only() {
    let toml = r#"
[server]
listen = "127.0.0.1:0"

[shadowsocks]
method = "chacha20-ietf-poly1305"

[[endpoint]]
path = "/pss"
kind = "ws_ss"
padded = true

[[endpoint]]
path = "/plain"
kind = "ws_ss_tcp"

[padding]
max_bytes = 128

[[users]]
id = "a"
password = "pw"
"#;
    let cfg = parse(toml).unwrap();
    assert!(cfg.padding.scheme_for_path("/pss").is_enabled(), "padded endpoint pads");
    assert!(
        !cfg.padding.scheme_for_path("/plain").is_enabled(),
        "plain endpoint stays plain"
    );
    assert_eq!(cfg.padding.padded_paths, vec!["/pss".to_string()]);
}

/// A minimal full-TOML config: `[server]` + `[shadowsocks]` + `endpoints` +
/// one password user. Feeds `loader::parse`, which merges/defaults/validates
/// exactly like a real config file, so the endpoint-conflict checks below
/// (which live in `Config::validate`) run through their real caller.
fn base(endpoints: &str) -> String {
    format!(
        "[server]\nlisten = \"127.0.0.1:0\"\n\
         [shadowsocks]\nmethod = \"chacha20-ietf-poly1305\"\n\
         {endpoints}\n\
         [[users]]\nid = \"a\"\npassword = \"pw\"\n"
    )
}

#[test]
fn duplicate_endpoint_path_is_rejected() {
    let toml = base(
        "[[endpoint]]\npath = \"/x\"\nkind = \"ws_ss_tcp\"\n\
         [[endpoint]]\npath = \"/x\"\nkind = \"ws_vless\"\n",
    );
    let err = parse(&toml).unwrap_err();
    assert!(err.to_string().contains("duplicate") || err.to_string().contains("distinct"));
}

#[test]
fn tcp_and_udp_endpoints_may_not_share_a_path() {
    let toml = base(
        "[[endpoint]]\npath = \"/x\"\nkind = \"ws_ss_tcp\"\n\
         [[endpoint]]\npath = \"/x\"\nkind = \"ws_ss_udp\"\n",
    );
    assert!(parse(&toml).is_err());
}

#[test]
fn combined_ss_endpoint_is_accepted() {
    let toml = base("[[endpoint]]\npath = \"/pss\"\nkind = \"ws_ss\"\npadded = true\n");
    assert!(parse(&toml).is_ok());
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
    let mut cfg = base_config();
    cfg.http_root_auth = true;
    cfg.endpoints = vec![ep("/", EndpointKind::WsSsTcp)];
    let error = cfg.validate().unwrap_err().to_string();

    assert!(error.contains("http_root_auth requires all websocket paths to differ from '/'"));
}

#[test]
fn accepts_xhttp_ss_tcp_endpoint_with_password_user() {
    // base_config has a password user, so an SS-over-XHTTP endpoint is valid.
    let mut cfg = base_config();
    cfg.endpoints = vec![ep("/ss", EndpointKind::XhttpSsTcp)];
    cfg.validate().unwrap();
}

#[test]
fn accepts_combined_ws_ss_endpoint() {
    // The opt-in combined kind: one endpoint path carries both legs, told
    // apart by the hidden token bit. Must validate.
    let mut cfg = base_config();
    cfg.endpoints = vec![ep("/both", EndpointKind::WsSs)];
    cfg.validate().unwrap();
}

#[test]
fn accepts_combined_xhttp_ss_endpoint() {
    // Same on the XHTTP carrier: `xhttp_ss` is one endpoint for both legs.
    let mut cfg = base_config();
    cfg.endpoints = vec![ep("/ssc", EndpointKind::XhttpSs)];
    cfg.validate().unwrap();
}

#[test]
fn rejects_two_endpoints_sharing_one_path() {
    // A path must be claimed by exactly one endpoint — sharing a value across
    // two different protocol kinds is a conflict, not an implicit combine.
    let mut cfg = base_config();
    cfg.endpoints =
        vec![ep("/shared", EndpointKind::WsSs), ep("/shared", EndpointKind::XhttpSsTcp)];
    let error = cfg.validate().unwrap_err().to_string();

    assert!(error.contains("distinct"), "got: {error}");
}

#[test]
fn ss_endpoint_without_password_user_still_validates() {
    // A vless-only user (no password) cannot back an SS endpoint. This used
    // to be a hard bail; it is now a warning (see `Config::validate`) — the
    // endpoint is simply unreachable, which by itself is not a config error.
    let mut cfg = base_config();
    cfg.users[0].password = None;
    cfg.users[0].vless_id = Some("00000000-0000-0000-0000-000000000001".into());
    cfg.endpoints = vec![ep("/ss", EndpointKind::XhttpSsTcp)];
    cfg.validate()
        .expect("a password-less SS endpoint warns, it does not bail");
}

#[test]
fn vless_endpoint_without_vless_id_user_still_validates() {
    // Same downgrade on the VLESS side: an endpoint with no vless_id user
    // warns instead of bailing. base_config's only user has a password and
    // no vless_id.
    let mut cfg = base_config();
    cfg.endpoints = vec![ep("/vless", EndpointKind::WsVless)];
    cfg.validate()
        .expect("a vless_id-less VLESS endpoint warns, it does not bail");
}

#[test]
fn rejects_xhttp_ss_tcp_endpoint_sharing_a_path_with_xhttp_vless() {
    // One path serves one protocol — a shared path is rejected even across
    // an SS and a VLESS endpoint.
    let mut cfg = base_config();
    cfg.users[0].vless_id = Some("00000000-0000-0000-0000-000000000001".into());
    cfg.endpoints = vec![ep("/x", EndpointKind::XhttpVless), ep("/x", EndpointKind::XhttpSsTcp)];
    let error = cfg.validate().unwrap_err().to_string();
    assert!(error.contains("duplicate endpoint path"), "got: {error}");
}

#[test]
fn accepts_xhttp_ss_udp_endpoint_with_password_user() {
    let mut cfg = base_config();
    cfg.endpoints = vec![ep("/ssu", EndpointKind::XhttpSsUdp)];
    cfg.validate().unwrap();
}

#[test]
fn allows_vless_only_users() {
    let mut cfg = base_config();
    cfg.endpoints = vec![ep("/vless", EndpointKind::WsVless)];
    cfg.users = vec![super::super::UserEntry {
        id: "550e8400-e29b-41d4-a716-446655440000".into(),
        password: None,
        fwmark: None,
        method: None,
        vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
        enabled: None,
        aliases: None,
    }];
    cfg.validate().unwrap();
}

#[test]
fn rejects_vless_endpoint_path_conflict_with_tcp_endpoint_path() {
    let mut cfg = base_config();
    cfg.users.push(super::super::UserEntry {
        id: "550e8400-e29b-41d4-a716-446655440000".into(),
        password: None,
        fwmark: None,
        method: None,
        vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
        enabled: None,
        aliases: None,
    });
    cfg.endpoints = vec![ep("/tcp", EndpointKind::WsSsTcp), ep("/tcp", EndpointKind::WsVless)];
    let error = cfg.validate().unwrap_err().to_string();

    assert!(error.contains("duplicate endpoint path"), "got: {error}");
}

#[test]
fn allows_vless_id_without_any_endpoint() {
    // Raw VLESS-over-QUIC and the reverse-tunnel dialer were removed, so a
    // vless_id user with no matching endpoint no longer has a forward
    // transport. That is not a validation error: the user is warned about
    // and skipped at route-build time (see `services::build`), so an
    // otherwise-valid config still starts.
    let mut cfg = base_config();
    cfg.users = vec![super::super::UserEntry {
        id: "alice".into(),
        password: None,
        fwmark: None,
        method: None,
        vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
        enabled: None,
        aliases: None,
    }];
    cfg.validate().unwrap();
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

#[test]
fn valid_user_aliases_pass_validation() {
    let mut cfg = base_config();
    cfg.users[0].aliases = Some(aliases(&[("mobile", "10.0.0.0/8"), ("office", "192.0.2.0/24")]));
    assert!(cfg.validate().is_ok());
}

#[test]
fn user_alias_with_malformed_cidr_is_rejected() {
    let mut cfg = base_config();
    cfg.users[0].aliases = Some(aliases(&[("mobile", "not-a-cidr")]));
    let error = cfg.validate().unwrap_err().to_string();
    assert!(error.contains("ip/cidr") || error.contains("alias"), "got: {error}");
}

/// A minimal enabled `[cluster]`, since only its presence gates the check
/// below; shard, PSK and peers are irrelevant to a user name.
fn cluster_config() -> crate::config::ClusterConfig {
    crate::config::ClusterConfig {
        shard: outline_wire::cluster::ShardId::new(0).expect("shard 0 is valid"),
        psk: crate::config::ClusterPsk::from_bytes(vec![7; 32]),
        mesh_listen: "127.0.0.1:9443".parse().unwrap(),
        mesh_relay_budget: std::time::Duration::from_millis(4000),
        peers: std::collections::HashMap::new(),
    }
}

fn config_with_cluster_and_user(name: &str) -> Config {
    let mut cfg = base_config();
    cfg.users[0].id = name.to_owned();
    cfg.cluster = Some(cluster_config());
    cfg
}

#[test]
fn config_rejects_a_user_name_that_cannot_cross_the_mesh() {
    // Paths and credentials are per-node now, but user *names* must agree across
    // nodes: `take_for_resume` is keyed by (session id, user), and the name
    // travels in a `UserFrame` bounded at `MAX_USER_LEN`. A name that cannot fit
    // could never authenticate a relayed session, so it fails at load instead of
    // at the first relay.
    let too_long = "u".repeat(crate::server::MAX_USER_LEN + 1);
    let error = config_with_cluster_and_user(&too_long)
        .validate()
        .expect_err("a name that cannot fit a UserFrame must be refused")
        .to_string();
    assert!(error.contains("mesh user name bound"), "got: {error}");

    let error = config_with_cluster_and_user("")
        .validate()
        .expect_err("an empty name can never match a park owner")
        .to_string();
    assert!(error.contains("empty user name"), "got: {error}");
}

#[test]
fn config_accepts_user_names_within_the_mesh_bound() {
    config_with_cluster_and_user("beerloga")
        .validate()
        .expect("an ordinary name loads");
    config_with_cluster_and_user(&"u".repeat(crate::server::MAX_USER_LEN))
        .validate()
        .expect("a name exactly at the ceiling loads");
}

#[test]
fn config_rejects_an_alias_name_that_cannot_cross_the_mesh() {
    // The name in a `UserFrame` is the *effective accounting label*, which is the
    // alias whenever the peer matches its subnet — so an alias that cannot fit
    // the frame fails at the first relay from such a peer, and nowhere else.
    // Same bound, same load-time refusal as the base id.
    let mut cfg = config_with_cluster_and_user("beerloga");
    let too_long = "a".repeat(crate::server::MAX_USER_LEN + 1);
    cfg.users[0].aliases = Some(aliases(&[(too_long.as_str(), "10.0.0.0/8")]));
    let error = cfg
        .validate()
        .expect_err("an alias that cannot fit a UserFrame must be refused")
        .to_string();
    assert!(error.contains("mesh user name bound"), "got: {error}");
    assert!(error.contains("[users.aliases]"), "the error must name the key to fix: {error}");

    // An empty alias is already refused a step earlier, by the alias validator
    // that runs for every server — clustered or not. Pin that it stays refused;
    // which of the two checks fires first does not matter to the operator.
    let mut cfg = config_with_cluster_and_user("beerloga");
    cfg.users[0].aliases = Some(aliases(&[("", "10.0.0.0/8")]));
    let error = cfg
        .validate()
        .expect_err("an empty alias can never match a park owner")
        .to_string();
    assert!(error.contains("empty alias name"), "got: {error}");
}

#[test]
fn config_accepts_alias_names_within_the_mesh_bound() {
    let mut cfg = config_with_cluster_and_user("beerloga");
    cfg.users[0].aliases = Some(aliases(&[("mobile", "10.0.0.0/8")]));
    cfg.validate().expect("an ordinary alias loads");
}

#[test]
fn the_alias_name_bound_applies_only_to_a_clustered_server() {
    let mut cfg = base_config();
    cfg.users[0].aliases =
        Some(aliases(&[(&"a".repeat(crate::server::MAX_USER_LEN + 1), "10.0.0.0/8")]));
    cfg.validate()
        .expect("an unclustered server is unaffected by the mesh bound");
}

#[test]
fn the_user_name_bound_applies_only_to_a_clustered_server() {
    // A standalone server never sends a UserFrame, so its names are its own
    // business — do not break existing single-node deployments.
    let mut cfg = base_config();
    cfg.users[0].id = "u".repeat(crate::server::MAX_USER_LEN + 1);
    cfg.validate()
        .expect("an unclustered server is unaffected by the mesh bound");
}

#[test]
fn alias_colliding_with_a_user_id_is_rejected() {
    // An alias name must not equal any user id (here, the user's own id) — that
    // would silently merge accounting under one label.
    let mut cfg = base_config();
    cfg.users[0].aliases = Some(aliases(&[("default", "192.0.2.0/24")]));
    let error = cfg.validate().unwrap_err().to_string();
    assert!(error.contains("collides") || error.contains("unique"), "got: {error}");
}
