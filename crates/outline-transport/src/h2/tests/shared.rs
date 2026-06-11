use super::H2ConnectionKey;
use crate::shared_cache::should_reuse_connection;

#[test]
fn h2_shared_connection_key_distinguishes_scheme_server_name_port_and_fwmark() {
    let base = H2ConnectionKey::new("one.example", 443, true, None);

    assert_ne!(base, H2ConnectionKey::new("two.example", 443, true, None));
    assert_ne!(base, H2ConnectionKey::new("one.example", 443, false, None));
    assert_ne!(base, H2ConnectionKey::new("one.example", 443, true, Some(42)));
    assert_ne!(base, H2ConnectionKey::new("one.example", 8443, true, None));
    assert_eq!(base, H2ConnectionKey::new("one.example", 443, true, None));
}

#[test]
fn probe_sources_do_not_reuse_shared_h2_connections() {
    assert!(should_reuse_connection("direct"));
    assert!(should_reuse_connection("standby_tcp"));
    assert!(!should_reuse_connection("probe_ws"));
    assert!(!should_reuse_connection("probe_http"));
}
