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
