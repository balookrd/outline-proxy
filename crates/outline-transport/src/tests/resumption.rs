use super::*;

#[test]
fn round_trip_hex() {
    let id = SessionId::from_bytes([0xAB; 16]);
    let hex = id.to_hex();
    assert_eq!(hex.len(), SessionId::HEX_LEN);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    let parsed = SessionId::parse_hex(&hex).unwrap();
    assert_eq!(id, parsed);
}

#[test]
fn parse_hex_rejects_invalid_length() {
    assert!(SessionId::parse_hex("").is_none());
    assert!(SessionId::parse_hex(&"a".repeat(31)).is_none());
    assert!(SessionId::parse_hex(&"a".repeat(33)).is_none());
}

#[test]
fn parse_hex_accepts_uppercase_and_normalises_to_lowercase() {
    let id = SessionId::parse_hex("0123456789ABCDEFFEDCBA9876543210").unwrap();
    assert_eq!(id.to_hex(), "0123456789abcdeffedcba9876543210");
}

#[test]
fn debug_output_does_not_leak_full_token() {
    let id = SessionId::from_bytes([0xAB; 16]);
    let debug = format!("{id:?}");
    assert!(debug.starts_with("SessionId("));
    assert!(debug.contains("abababab"));
    assert!(!debug.contains(&id.to_hex()));
}

#[test]
fn resume_cache_round_trip() {
    let cache = ResumeCache::new_uninit();
    let id = SessionId::from_bytes([0x42; 16]);
    assert!(cache.get("uplink-a").is_none());
    cache.store("uplink-a", id);
    assert_eq!(cache.get("uplink-a"), Some(id));
    assert_eq!(cache.len(), 1);
}

#[test]
fn resume_cache_overwrites_per_key() {
    let cache = ResumeCache::new_uninit();
    let a = SessionId::from_bytes([0x01; 16]);
    let b = SessionId::from_bytes([0x02; 16]);
    cache.store("uplink-x", a);
    cache.store("uplink-x", b);
    assert_eq!(cache.get("uplink-x"), Some(b));
    assert_eq!(cache.len(), 1);
}

#[test]
fn resume_cache_forget_removes_entry() {
    let cache = ResumeCache::new_uninit();
    cache.store("uplink-y", SessionId::from_bytes([7; 16]));
    cache.forget("uplink-y");
    assert!(cache.get("uplink-y").is_none());
    assert_eq!(cache.len(), 0);
}

#[test]
fn store_if_issued_skips_none() {
    let cache = ResumeCache::new_uninit();
    cache.store_if_issued("uplink-z", None);
    assert_eq!(cache.len(), 0);
    cache.store_if_issued("uplink-z", Some(SessionId::from_bytes([9; 16])));
    assert_eq!(cache.len(), 1);
}

#[test]
fn resume_cache_evicts_oldest_inserted_at_capacity() {
    let cache = ResumeCache::new_uninit();
    let id = SessionId::from_bytes([1; 16]);
    for i in 0..RESUME_CACHE_CAPACITY {
        cache.store(format!("uplink-{i}#tcp"), id);
    }
    assert_eq!(cache.len(), RESUME_CACHE_CAPACITY);
    cache.store("overflow#tcp", id);
    assert_eq!(cache.len(), RESUME_CACHE_CAPACITY);
    assert!(cache.get("uplink-0#tcp").is_none(), "oldest entry must be evicted");
    assert_eq!(cache.get("overflow#tcp"), Some(id));
    assert_eq!(cache.get("uplink-1#tcp"), Some(id));
}

#[test]
fn resume_cache_overwrite_at_capacity_does_not_evict() {
    let cache = ResumeCache::new_uninit();
    let a = SessionId::from_bytes([1; 16]);
    let b = SessionId::from_bytes([2; 16]);
    for i in 0..RESUME_CACHE_CAPACITY {
        cache.store(format!("uplink-{i}#tcp"), a);
    }
    cache.store("uplink-0#tcp", b);
    assert_eq!(cache.len(), RESUME_CACHE_CAPACITY);
    assert_eq!(cache.get("uplink-0#tcp"), Some(b));
    assert_eq!(cache.get(&format!("uplink-{}#tcp", RESUME_CACHE_CAPACITY - 1)), Some(a));
}

#[test]
fn resume_cache_forget_then_reinsert_treats_key_as_newest() {
    let cache = ResumeCache::new_uninit();
    let id = SessionId::from_bytes([3; 16]);
    for i in 0..RESUME_CACHE_CAPACITY {
        cache.store(format!("uplink-{i}#tcp"), id);
    }
    cache.forget("uplink-0#tcp");
    cache.store("uplink-0#tcp", id);
    assert_eq!(cache.len(), RESUME_CACHE_CAPACITY);
    // The re-inserted key is now the newest; the next eviction must
    // take uplink-1, not the re-inserted uplink-0.
    cache.store("overflow#tcp", id);
    assert!(cache.get("uplink-1#tcp").is_none());
    assert_eq!(cache.get("uplink-0#tcp"), Some(id));
}

fn datagram_offer() -> crate::dial_plan::DialResumeOptions {
    crate::dial_plan::DialResumeOptions {
        udp_datagram_requested: true,
        ..Default::default()
    }
}

#[test]
fn udp_datagram_offer_sets_the_request_header() {
    let mut headers = http::HeaderMap::new();
    apply_udp_datagram_request_header(&datagram_offer(), &mut headers);
    assert_eq!(headers.get(UDP_DATAGRAM_HEADER).unwrap(), "1");

    let mut headers = http::HeaderMap::new();
    apply_udp_datagram_request_header(&Default::default(), &mut headers);
    assert!(headers.get(UDP_DATAGRAM_HEADER).is_none());
}

#[test]
fn shared_resume_headers_never_carry_the_udp_datagram_offer() {
    // The h1 / h2 carriers (also an h3 dial's fallbacks) write only these, so
    // the offer must not leak onto them.
    let mut headers = http::HeaderMap::new();
    apply_resume_request_headers(&datagram_offer(), &mut headers);
    assert!(headers.get(UDP_DATAGRAM_HEADER).is_none());
}

#[test]
fn udp_datagram_accepted_needs_offer_and_echo() {
    let mut echo = http::HeaderMap::new();
    echo.insert(UDP_DATAGRAM_HEADER, http::HeaderValue::from_static("1"));
    assert!(parse_resume_response_echo(&datagram_offer(), &echo).udp_datagram_accepted);
    // Echo without an offer: spurious.
    assert!(!parse_resume_response_echo(&Default::default(), &echo).udp_datagram_accepted);
    // Offer without an echo: declined.
    let none = http::HeaderMap::new();
    assert!(!parse_resume_response_echo(&datagram_offer(), &none).udp_datagram_accepted);
    // Any value other than `1` is not an acceptance.
    let mut other = http::HeaderMap::new();
    other.insert(UDP_DATAGRAM_HEADER, http::HeaderValue::from_static("0"));
    assert!(!parse_resume_response_echo(&datagram_offer(), &other).udp_datagram_accepted);
}
