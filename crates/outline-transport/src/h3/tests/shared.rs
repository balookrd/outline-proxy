use super::{H3ConnectionKey, choose_slot};
use crate::shared_cache::should_reuse_connection;

const MIN: u8 = 4;
const CAP: u64 = 32;

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
fn choose_slot_grows_to_min_carriers_for_isolation() {
    // Below the MIN floor the picker opens a fresh empty slot rather than
    // packing onto an existing carrier — that is what isolates a long-lived SSE
    // from the bulk of the traffic on a lightly-loaded host.
    assert_eq!(choose_slot(&[None, None, None, None], MIN, CAP), 0);
    assert_eq!(choose_slot(&[Some(1), None, None, None], MIN, CAP), 1);
    assert_eq!(choose_slot(&[Some(1), Some(1), None, None], MIN, CAP), 2);
    // Even a nearly-idle carrier (active 0) does not stop the floor from growing.
    assert_eq!(choose_slot(&[Some(0), Some(0), Some(0), None, None], MIN, CAP), 3);
}

#[test]
fn choose_slot_packs_least_loaded_once_at_floor() {
    // At the floor the picker balances load; ties resolve to the lowest slot.
    assert_eq!(choose_slot(&[Some(2), Some(2), Some(2), Some(2)], MIN, CAP), 0);
    assert_eq!(choose_slot(&[Some(3), Some(1), Some(2), Some(2)], MIN, CAP), 1);
}

#[test]
fn choose_slot_grows_when_all_carriers_at_cap() {
    // Floor met and every populated carrier saturated → open a new carrier.
    let loads = [Some(CAP), Some(CAP), Some(CAP), Some(CAP), None, None];
    assert_eq!(choose_slot(&loads, MIN, CAP), 4);
}

#[test]
fn choose_slot_soft_overflows_when_pool_full() {
    // Every slot populated and at/over CAP (MAX carriers reached) → soft-overflow
    // onto the least-loaded carrier overall; ties resolve to the lowest slot.
    let loads = [Some(CAP + 1), Some(CAP), Some(CAP + 2), Some(CAP)];
    assert_eq!(choose_slot(&loads, MIN, CAP), 1);
}

#[test]
fn probe_sources_do_not_reuse_shared_h3_connections() {
    assert!(should_reuse_connection("socks_tcp"));
    assert!(should_reuse_connection("standby_udp"));
    assert!(!should_reuse_connection("probe_ws"));
    assert!(!should_reuse_connection("probe_http"));
}
