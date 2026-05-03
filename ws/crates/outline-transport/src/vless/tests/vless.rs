use std::collections::HashMap;
use std::sync::Arc;

use socks5_proto::TargetAddr;

use super::header::{
    VLESS_ATYP_DOMAIN, VLESS_ATYP_IPV4, VLESS_CMD_TCP, VLESS_CMD_UDP, build_request_header,
};
use super::parse_uuid;
use super::udp_mux::{VlessUdpSessionSlot, evict_lru_populated_session};

#[test]
fn parse_uuid_roundtrip() {
    let id = parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
    assert_eq!(id[0], 0x55);
    assert_eq!(id[15], 0x00);
}

#[test]
fn request_header_ipv4_tcp() {
    let uuid = parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let target = TargetAddr::IpV4(std::net::Ipv4Addr::new(1, 2, 3, 4), 443);
    let hdr = build_request_header(&uuid, VLESS_CMD_TCP, &target, &[]);
    assert_eq!(hdr[0], 0x00);
    assert_eq!(&hdr[1..17], &uuid);
    assert_eq!(hdr[17], 0x00);
    assert_eq!(hdr[18], 0x01);
    assert_eq!(&hdr[19..21], &443u16.to_be_bytes());
    assert_eq!(hdr[21], VLESS_ATYP_IPV4);
    assert_eq!(&hdr[22..26], &[1, 2, 3, 4]);
}

#[test]
fn request_header_domain_udp() {
    let uuid = parse_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let target = TargetAddr::Domain("example.com".into(), 80);
    let hdr = build_request_header(&uuid, VLESS_CMD_UDP, &target, &[]);
    assert_eq!(hdr[18], VLESS_CMD_UDP);
    assert_eq!(&hdr[19..21], &80u16.to_be_bytes());
    assert_eq!(hdr[21], VLESS_ATYP_DOMAIN);
    assert_eq!(hdr[22], 11);
    assert_eq!(&hdr[23..23 + 11], b"example.com");
}

#[test]
fn vless_udp_session_slot_empty_uses_created_for_lru() {
    // The LRU comparator and idle-session janitor both call
    // `slot.last_use()`. For in-flight (cell-empty) slots that
    // must fall back to `created` so the comparator has a totally-
    // ordered key — otherwise `min_by_key` would compare an
    // `Option<Instant>` and skip empty slots, but the predicate
    // for the janitor must still expire stuck dials.
    let slot = VlessUdpSessionSlot::new();
    assert!(slot.entry().is_none(), "freshly built slot is empty");
    assert_eq!(
        slot.last_use(),
        slot.created,
        "empty slot's LRU stamp falls back to creation time"
    );
}

#[test]
fn evict_lru_populated_session_skips_in_flight_slots() {
    // Only populated slots are eligible for eviction — abandoning
    // an in-flight dial would cancel the shared OnceCell future
    // and force every blocked `session_for` waiter to restart.
    // The eviction scan must filter `entry().is_some()` first.
    let mut map: HashMap<TargetAddr, Arc<VlessUdpSessionSlot>> = HashMap::new();
    let target = TargetAddr::IpV4(std::net::Ipv4Addr::new(1, 2, 3, 4), 443);
    map.insert(target.clone(), Arc::new(VlessUdpSessionSlot::new()));

    let evicted = evict_lru_populated_session(&mut map);
    assert!(evicted.is_none(), "in-flight slot must not be evicted");
    assert_eq!(map.len(), 1, "in-flight slot stays in the map");
}
