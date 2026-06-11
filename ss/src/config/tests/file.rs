use super::FileConfig;

#[test]
fn parses_sectioned_ws_paths() {
    let config: FileConfig = toml::from_str(
        r#"
[server]
listen = "0.0.0.0:3000"

[websocket]
ws_path_tcp = "/custom-tcp"
ws_path_udp = "/custom-udp"
ws_path_vless = "/vless"

[http_root]
auth = true
realm = "VPN"

[[users]]
id = "alice"
password = "secret"
ws_path_tcp = "/alice-tcp"
ws_path_udp = "/alice-udp"
"#,
    )
    .unwrap();

    let ws = config.websocket.unwrap();
    assert_eq!(ws.ws_path_tcp.as_deref(), Some("/custom-tcp"));
    assert_eq!(ws.ws_path_udp.as_deref(), Some("/custom-udp"));
    assert_eq!(ws.ws_path_vless.as_deref(), Some("/vless"));
    let http_root = config.http_root.unwrap();
    assert_eq!(http_root.auth, Some(true));
    assert_eq!(http_root.realm.as_deref(), Some("VPN"));
    let users = config.users.unwrap();
    assert_eq!(users[0].ws_path_tcp.as_deref(), Some("/alice-tcp"));
    assert_eq!(users[0].ws_path_udp.as_deref(), Some("/alice-udp"));
}

#[test]
fn parses_server_sections() {
    let config: FileConfig = toml::from_str(
        r#"
[server]
listen = "0.0.0.0:3000"
tls_cert_path = "./cert.pem"
tls_key_path = "./key.pem"

[server.ss]
listen = "0.0.0.0:8388"

[server.h3]
listen = "0.0.0.0:3000"
cert_path = "./cert.pem"
key_path = "./key.pem"
"#,
    )
    .unwrap();

    let server = config.server.unwrap();
    assert_eq!(server.listen.unwrap().to_string(), "0.0.0.0:3000");
    assert_eq!(server.ss.unwrap().listen.unwrap().to_string(), "0.0.0.0:8388");
    let h3 = server.h3.unwrap();
    assert_eq!(h3.listen.unwrap().to_string(), "0.0.0.0:3000");
    assert!(h3.cert_path.is_some());
}

#[test]
fn parses_server_certs_with_unified_names() {
    // New canonical naming: `cert_path` / `key_path` in [server], same
    // as in [server.h3]. Plus an array of additional cert/key/sni
    // triples for SNI-based selection.
    let config: FileConfig = toml::from_str(
        r#"
[server]
listen = "0.0.0.0:443"
cert_path = "./default.pem"
key_path  = "./default.key"

[[server.certs]]
cert_path = "./api.pem"
key_path  = "./api.key"
sni = ["api.example.com", "api2.example.com"]

[[server.certs]]
cert_path = "./derived-from-san.pem"
key_path  = "./derived-from-san.key"

[server.h3]
listen = "0.0.0.0:443"

[[server.h3.certs]]
cert_path = "./h3.pem"
key_path  = "./h3.key"
"#,
    )
    .unwrap();

    let server = config.server.unwrap();
    assert!(server.cert_path.is_some());
    assert!(server.key_path.is_some());
    let certs = server.certs.unwrap();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].sni.as_deref().map(|s| s.len()), Some(2));
    assert!(certs[1].sni.is_none());
    let h3 = server.h3.unwrap();
    assert_eq!(h3.certs.unwrap().len(), 1);
}

#[test]
fn legacy_tls_cert_path_aliases_are_accepted() {
    // The old `tls_cert_path` / `tls_key_path` keys still parse — they
    // are serde aliases of the new `cert_path` / `key_path`.
    let config: FileConfig = toml::from_str(
        r#"
[server]
listen = "0.0.0.0:3000"
tls_cert_path = "./old.pem"
tls_key_path  = "./old.key"
"#,
    )
    .unwrap();
    let server = config.server.unwrap();
    assert_eq!(server.cert_path.as_deref().and_then(|p| p.to_str()), Some("./old.pem"));
    assert_eq!(server.key_path.as_deref().and_then(|p| p.to_str()), Some("./old.key"));
}

#[test]
fn parses_tuning_profile_and_overrides() {
    let config: FileConfig = toml::from_str(
        r#"
tuning_profile = "medium"

[server]
listen = "0.0.0.0:3000"

[tuning]
h3_udp_socket_buffer_bytes = 2097152
h3_max_concurrent_bidi_streams = 128
"#,
    )
    .unwrap();

    assert_eq!(config.tuning_profile, Some(super::TuningPreset::Medium));
    let tuning = config.tuning.unwrap();
    assert_eq!(tuning.h3_udp_socket_buffer_bytes, Some(2_097_152));
    assert_eq!(tuning.h3_max_concurrent_bidi_streams, Some(128));
    assert_eq!(tuning.h3_connection_window_bytes, None);
}

#[test]
fn parses_dashboard_instances() {
    let config: FileConfig = toml::from_str(
        r#"
[server]
listen = "0.0.0.0:3000"

[dashboard]
listen = "127.0.0.1:7002"

[[dashboard.instances]]
name = "local"
control_url = "http://127.0.0.1:7001"
token_file = "./control.token"
"#,
    )
    .unwrap();

    let dashboard = config.dashboard.unwrap();
    assert_eq!(dashboard.listen.unwrap().to_string(), "127.0.0.1:7002");
    let instances = dashboard.instances.unwrap();
    assert_eq!(instances[0].name.as_deref(), Some("local"));
    assert_eq!(instances[0].control_url.as_deref(), Some("http://127.0.0.1:7001"));
}

#[test]
fn rejects_unknown_tuning_fields() {
    let error = toml::from_str::<FileConfig>(
        r#"
[server]
listen = "0.0.0.0:3000"

[tuning]
not_a_real_field = 123
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("unknown field"));
    assert!(error.contains("not_a_real_field"));
}

#[test]
fn rejects_legacy_top_level_keys() {
    let error = toml::from_str::<FileConfig>(
        r#"
listen = "0.0.0.0:3000"
ws_path_tcp = "/tcp"
"#,
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("unknown field"));
}
