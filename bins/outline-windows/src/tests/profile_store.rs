use crate::profile_store::{ProfileStore, ServerProfile};

#[test]
fn test_parse_vless_share_link() {
    let link = "vless://11111111-2222-3333-4444-555555555555@edge.example.com:443?security=tls&alpn=h3,h2&type=ws&path=%2Fsecret#Tokyo%20Edge";
    let profile = ServerProfile::from_link(link).expect("should parse vless link");

    assert_eq!(profile.name, "Tokyo Edge");
    assert_eq!(profile.transport, "vless");
    assert_eq!(profile.link, link);
    assert_eq!(profile.server_host(), Some("edge.example.com".to_string()));
    assert!(!profile.is_subscription());
}

#[test]
fn test_parse_ss_sip002_share_link() {
    let link =
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpQYXNzd29yZDEyMw==@ss.example.com:8443#Frankfurt%20SS";
    let profile = ServerProfile::from_link(link).expect("should parse ss link");

    assert_eq!(profile.name, "Frankfurt SS");
    assert_eq!(profile.transport, "ss");
    assert_eq!(profile.link, link);
    assert_eq!(profile.server_host(), Some("ss.example.com".to_string()));
    assert!(!profile.is_subscription());
}

#[test]
fn test_parse_outline_wrapped_ss_link() {
    let link = "outline://ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpQYXNzd29yZDEyMw==@outline.example.com:9443#Outline%20Node";
    let profile = ServerProfile::from_link(link).expect("should parse outline wrapped link");

    assert_eq!(profile.name, "Outline Node");
    assert_eq!(profile.transport, "ss");
    assert!(profile.link.starts_with("ss://"));
    assert_eq!(profile.server_host(), Some("outline.example.com".to_string()));
}

#[test]
fn test_parse_subscription_url() {
    let url = "https://sub.beerloga.su/api/v1/client/subscribe?token=abc123xyz";
    let profile = ServerProfile::from_link(url).expect("should parse subscription url");

    assert_eq!(profile.name, "Subscription");
    assert_eq!(profile.transport, "subscription");
    assert_eq!(profile.config_url, url);
    assert!(profile.link.is_empty());
    assert!(profile.is_subscription());
}

#[test]
fn test_profile_store_crud_and_persistence() {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let file_path = temp_dir.path().join("profiles.json");

    let store = ProfileStore::open(file_path.clone()).expect("open store");
    assert!(store.profiles().is_empty());
    assert!(store.active_profile().is_none());

    // Add profile 1
    let p1 = ServerProfile {
        id: "p1".into(),
        name: "Profile 1".into(),
        transport: "vless".into(),
        link: "vless://uuid@host1:443#P1".into(),
        padding_enabled: true,
        tcp_only: false,
        raw_toml_override: "".into(),
        config_url: "".into(),
        cached_toml: "".into(),
        updated_at: 100.0,
    };
    store.add_profile(p1).expect("add p1");

    assert_eq!(store.profiles().len(), 1);
    assert_eq!(store.active_profile_id(), Some("p1".to_string()));

    // Add profile 2
    let p2 = ServerProfile {
        id: "p2".into(),
        name: "Profile 2".into(),
        transport: "ss".into(),
        link: "ss://uuid@host2:443#P2".into(),
        padding_enabled: false,
        tcp_only: true,
        raw_toml_override: "".into(),
        config_url: "".into(),
        cached_toml: "".into(),
        updated_at: 200.0,
    };
    store.add_profile(p2).expect("add p2");
    assert_eq!(store.profiles().len(), 2);

    // Select profile 2
    store.select_profile("p2").expect("select p2");
    assert_eq!(store.active_profile().unwrap().id, "p2");

    // Update profile 1
    let mut p1_updated = store.profiles().into_iter().find(|p| p.id == "p1").unwrap();
    p1_updated.name = "Profile 1 Renamed".into();
    store.update_profile(p1_updated).expect("update p1");
    assert_eq!(
        store.profiles().iter().find(|p| p.id == "p1").unwrap().name,
        "Profile 1 Renamed"
    );

    // Reopen store from disk and check persistence
    let reloaded = ProfileStore::open(file_path.clone()).expect("reload store");
    assert_eq!(reloaded.profiles().len(), 2);
    assert_eq!(reloaded.active_profile_id(), Some("p2".to_string()));
    assert_eq!(
        reloaded.profiles().iter().find(|p| p.id == "p1").unwrap().name,
        "Profile 1 Renamed"
    );

    // Remove active profile 2
    reloaded.remove_profile("p2").expect("remove p2");
    assert_eq!(reloaded.profiles().len(), 1);
    assert_eq!(reloaded.active_profile_id(), Some("p1".to_string()));
}
