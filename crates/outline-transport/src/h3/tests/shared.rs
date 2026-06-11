use super::H3ConnectionKey;
use crate::shared_cache::should_reuse_connection;

#[test]
fn h3_shared_connection_key_distinguishes_server_name_port_and_fwmark() {
    let base = H3ConnectionKey::new("example.com", 443, None);

    assert_eq!(base, H3ConnectionKey::new("example.com", 443, None));
    assert_ne!(base, H3ConnectionKey::new("example.net", 443, None));
    assert_ne!(base, H3ConnectionKey::new("example.com", 443, Some(100)));
    assert_ne!(base, H3ConnectionKey::new("example.com", 8443, None));
}

#[test]
fn probe_sources_do_not_reuse_shared_h3_connections() {
    assert!(should_reuse_connection("socks_tcp"));
    assert!(should_reuse_connection("standby_udp"));
    assert!(!should_reuse_connection("probe_ws"));
    assert!(!should_reuse_connection("probe_http"));
}
