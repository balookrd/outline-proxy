use super::FileConfig;

#[test]
fn parses_sectioned_ws_paths() {
    let config: FileConfig = toml::from_str(
        r#"
[server]
listen = "0.0.0.0:3000"

[websocket]
tcp_path = "/custom-tcp"
udp_path = "/custom-udp"
vless_path = "/vless"

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
    assert_eq!(ws.tcp_path.as_deref(), Some("/custom-tcp"));
    assert_eq!(ws.udp_path.as_deref(), Some("/custom-udp"));
    assert_eq!(ws.vless_path.as_deref(), Some("/vless"));
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
