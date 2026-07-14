use super::H3ConnectionKey;
use crate::shared_cache::should_reuse_connection;

#[test]
fn h3_shared_connection_key_distinguishes_server_name_port_and_fwmark() {
    let base = H3ConnectionKey::with_slot("example.com", 443, None, 0);

    assert_eq!(base, H3ConnectionKey::with_slot("example.com", 443, None, 0));
    assert_ne!(base, H3ConnectionKey::with_slot("example.net", 443, None, 0));
    assert_ne!(base, H3ConnectionKey::with_slot("example.com", 443, Some(100), 0));
    assert_ne!(base, H3ConnectionKey::with_slot("example.com", 8443, None, 0));
}

#[test]
fn h3_connection_key_distinguishes_carrier_slots() {
    // Distinct carrier slots must hash/compare unequal so each occupies its own
    // registry entry — that independence is what bounds the reconnect blast
    // radius when one carrier collapses.
    let slot0 = H3ConnectionKey::with_slot("example.com", 443, None, 0);
    let slot1 = H3ConnectionKey::with_slot("example.com", 443, None, 1);
    assert_ne!(slot0, slot1);
    assert_eq!(slot0, H3ConnectionKey::with_slot("example.com", 443, None, 0));
}

#[test]
fn probe_sources_do_not_reuse_shared_h3_connections() {
    assert!(should_reuse_connection("socks_tcp"));
    assert!(should_reuse_connection("standby_udp"));
    assert!(!should_reuse_connection("probe_ws"));
    assert!(!should_reuse_connection("probe_http"));
}
