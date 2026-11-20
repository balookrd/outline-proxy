use crate::config_generator::ConfigGenerator;
use crate::profile_store::ServerProfile;

#[test]
fn test_generate_socks5_config_vless() {
    let profile = ServerProfile {
        id: "test-1".into(),
        name: "Test Node".into(),
        transport: "vless".into(),
        link: "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&alpn=h2&type=ws&path=/ws#Test%20Node".into(),
        padding_enabled: true,
        tcp_only: false,
        raw_toml_override: "".into(),
        config_url: "".into(),
        cached_toml: "".into(),
        updated_at: 0.0,
    };

    let toml = ConfigGenerator::generate(&profile, false, 1080, false);

    assert!(toml.contains("[socks5]"));
    assert!(toml.contains("listen = \"127.0.0.1:1080\""));
    assert!(!toml.contains("[tun]"));
    assert!(toml.contains("[[outline.uplinks]]"));
    assert!(toml.contains("name = \"Test Node\""));
    assert!(toml.contains("transport = \"vless\""));
    assert!(toml.contains("link = \"vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&alpn=h2&type=ws&path=/ws#Test%20Node\""));
    assert!(toml.contains("[padding]\nenabled = true"));
}

#[test]
fn test_generate_tun_config_vless() {
    let profile = ServerProfile {
        id: "test-2".into(),
        name: "TUN Node".into(),
        transport: "vless".into(),
        link: "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws".into(),
        padding_enabled: false,
        tcp_only: false,
        raw_toml_override: "".into(),
        config_url: "".into(),
        cached_toml: "".into(),
        updated_at: 0.0,
    };

    let toml = ConfigGenerator::generate(&profile, false, 2080, true);

    assert!(toml.contains("[socks5]"));
    assert!(toml.contains("listen = \"127.0.0.1:2080\""));
    assert!(toml.contains("[tun]"));
    assert!(toml.contains("name = \"OutlineProxy\""));
    assert!(toml.contains("mtu = 1500"));
    assert!(toml.contains("sniff_quic = true"));
    assert!(toml.contains("[tun.tcp]"));
    assert!(toml.contains("sniffing = true"));
}

#[test]
fn test_generate_tcp_only_replaces_h3_and_alpn() {
    let profile = ServerProfile {
        id: "test-3".into(),
        name: "H3 Node".into(),
        transport: "xhttp_h3".into(),
        link: "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&alpn=h3,h2&type=xhttp#H3%20Node".into(),
        padding_enabled: false,
        tcp_only: false,
        raw_toml_override: "".into(),
        config_url: "".into(),
        cached_toml: "".into(),
        updated_at: 0.0,
    };

    let toml = ConfigGenerator::generate(&profile, true, 1080, false);

    assert!(toml.contains("transport = \"xhttp_h2\""));
    assert!(!toml.contains("xhttp_h3"));
    assert!(toml.contains("alpn=h2"));
    assert!(!toml.contains("alpn=h3"));
}

#[test]
fn test_generate_from_cached_toml_strips_tun_when_socks_only() {
    let cached = r#"
[tun]
path = "utun"
mtu = 1500

[[outline.uplinks]]
name = "cached-up"
transport = "ws_h3"
link = "vless://uuid@host:443?type=ws&alpn=h3"
"#;

    let profile = ServerProfile {
        id: "sub-1".into(),
        name: "Subscription".into(),
        transport: "subscription".into(),
        link: "".into(),
        padding_enabled: false,
        tcp_only: true,
        raw_toml_override: "".into(),
        config_url: "https://sub.example.com/api".into(),
        cached_toml: cached.into(),
        updated_at: 0.0,
    };

    let toml = ConfigGenerator::generate(&profile, false, 1080, false);

    assert!(!toml.contains("[tun]"));
    assert!(toml.contains("[socks5]"));
    assert!(toml.contains("transport = \"ws_h2\""));
    assert!(toml.contains("alpn=h2"));
}

#[test]
fn test_generate_from_cached_toml_replaces_wintun_adapter_name() {
    let cached = r#"
[socks5]
listen = "127.0.0.1:1080"

[tun]
path = "utun"
mtu = 1500
"#;

    let profile = ServerProfile {
        id: "sub-2".into(),
        name: "Subscription".into(),
        transport: "subscription".into(),
        link: "".into(),
        padding_enabled: false,
        tcp_only: false,
        raw_toml_override: "".into(),
        config_url: "https://sub.example.com/api".into(),
        cached_toml: cached.into(),
        updated_at: 0.0,
    };

    let toml = ConfigGenerator::generate(&profile, false, 1080, true);

    assert!(toml.contains("[tun]"));
    assert!(toml.contains("name = \"OutlineProxy\""));
    assert!(!toml.contains("path = \"utun\""));
}
