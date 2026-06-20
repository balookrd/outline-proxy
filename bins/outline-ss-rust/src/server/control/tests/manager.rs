use super::*;
use arc_swap::ArcSwap;

use crate::server::tests::sample_config;

/// Builds a `UserManager` whose only registered route surface is the default
/// tcp/udp paths from `sample_config`. `h3_alpn` controls whether raw
/// VLESS-over-QUIC counts as an available transport — exactly the bit
/// `validate_new` must honour to stay feature-equivalent with the startup
/// `config::validation` path.
fn manager_with_alpn(h3_alpn: Vec<H3Alpn>) -> UserManager {
    let mut config = sample_config("127.0.0.1:0".parse().unwrap());
    config.h3_alpn = h3_alpn;
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

// A `vless_id` user with no ws/xhttp path is valid *iff* raw VLESS-over-QUIC is
// enabled (`"vless"` in `[server.h3].alpn`) — the raw-QUIC ALPN is itself a
// transport. The control API must accept exactly what a fresh startup would, so
// this mirrors the `has_raw_quic` branch in `config::validation::validate`.
#[test]
fn vless_id_with_raw_quic_alpn_needs_no_ws_or_xhttp_path() {
    let manager = manager_with_alpn(vec![H3Alpn::H3, H3Alpn::Vless]);
    assert!(
        manager.validate_new(&vless_only_entry()).is_ok(),
        "raw VLESS-over-QUIC ALPN must satisfy the vless_id transport requirement, \
         matching startup validation"
    );
}

#[test]
fn vless_id_without_any_transport_is_rejected() {
    // No raw-QUIC VLESS and no ws/xhttp path: both startup and runtime reject.
    let manager = manager_with_alpn(vec![H3Alpn::H3]);
    assert!(
        manager.validate_new(&vless_only_entry()).is_err(),
        "vless_id with no ws/xhttp path and no raw-QUIC ALPN must be rejected"
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
    let manager = manager_with_alpn(vec![H3Alpn::H3]);
    let entry = ss_entry_with_aliases(&[("mobile", "10.0.0.0/8")]);
    assert!(manager.validate_new(&entry).is_ok());
}

#[test]
fn validate_new_rejects_malformed_alias_cidr() {
    // Control-plane parity with startup `config::validation`.
    let manager = manager_with_alpn(vec![H3Alpn::H3]);
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
