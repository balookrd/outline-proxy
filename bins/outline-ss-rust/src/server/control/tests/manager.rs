use super::*;
use arc_swap::ArcSwap;

use crate::server::tests::sample_config;

/// Builds a `UserManager` whose only registered route surface is the default
/// tcp/udp paths from `sample_config`.
fn test_manager() -> UserManager {
    let config = sample_config("127.0.0.1:0".parse().unwrap());
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
        xhttp_ss: Arc::new(std::collections::BTreeMap::new()),
        xhttp_ss_udp: Arc::new(std::collections::BTreeMap::new()),
    }));
    let auth: AuthUsersSnapshot =
        Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(Vec::<UserKey>::new()))));
    let tcp_paths = BTreeSet::from([config.ws_path_tcp.clone()]);
    let udp_paths = BTreeSet::from([config.ws_path_udp.clone()]);
    UserManager::new(
        &config,
        routes,
        auth,
        AllowedRoutePaths {
            tcp: tcp_paths,
            udp: udp_paths,
            vless: BTreeSet::new(),
            xhttp_vless: BTreeSet::new(),
            xhttp_ss: BTreeSet::new(),
            xhttp_ss_udp: BTreeSet::new(),
        },
    )
}

fn vless_only_entry() -> UserEntry {
    UserEntry {
        id: "v".into(),
        password: None,
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: Some("00000000-0000-0000-0000-000000000001".into()),
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

#[test]
fn vless_id_without_any_transport_is_rejected() {
    // A `vless_id` user needs a ws_path_vless or xhttp_path_vless. Raw
    // VLESS-over-QUIC was removed, so no ALPN can satisfy the requirement and
    // the live control API rejects such a user outright.
    let manager = test_manager();
    assert!(
        manager.validate_new(&vless_only_entry()).is_err(),
        "vless_id with no ws/xhttp path must be rejected"
    );
}

fn ss_entry_with_aliases(pairs: &[(&str, &str)]) -> UserEntry {
    let aliases = pairs
        .iter()
        .map(|(name, cidr)| (name.to_string(), crate::config::OneOrManyCidr::One(cidr.to_string())))
        .collect();
    UserEntry {
        id: "ss".into(),
        password: Some("secret".into()),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: Some(aliases),
    }
}

#[test]
fn validate_new_accepts_valid_aliases() {
    let manager = test_manager();
    let entry = ss_entry_with_aliases(&[("mobile", "10.0.0.0/8")]);
    assert!(manager.validate_new(&entry).is_ok());
}

#[test]
fn validate_new_rejects_malformed_alias_cidr() {
    // Control-plane parity with startup `config::validation`.
    let manager = test_manager();
    let entry = ss_entry_with_aliases(&[("mobile", "not-a-cidr")]);
    assert!(manager.validate_new(&entry).is_err());
}

#[test]
fn user_view_exposes_aliases() {
    let entry = ss_entry_with_aliases(&[("mobile", "10.0.0.0/8")]);
    let view = UserView::from(&entry);
    let aliases = view.aliases.expect("aliases should be exposed in the view");
    assert_eq!(aliases["mobile"].as_slice(), &["10.0.0.0/8".to_string()][..]);
}
