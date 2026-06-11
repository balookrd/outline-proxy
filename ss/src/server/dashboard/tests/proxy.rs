use super::*;

#[test]
fn instance_uri_preserves_base_path_prefix() {
    let uri = instance_uri("http://127.0.0.1:7001/admin", "/control/users").unwrap();
    assert_eq!(uri.to_string(), "http://127.0.0.1:7001/admin/control/users");
}

#[test]
fn instance_uri_supports_https() {
    let uri = instance_uri("https://edge.example.com:7443/admin", "/control/users").unwrap();
    assert_eq!(uri.to_string(), "https://edge.example.com:7443/admin/control/users");
}
