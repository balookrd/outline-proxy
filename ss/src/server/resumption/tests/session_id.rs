use super::*;

#[test]
fn round_trip_hex() {
    let rng = SystemRandom::new();
    let id = SessionId::random(&rng).unwrap();
    let hex = id.to_hex();
    assert_eq!(hex.len(), SessionId::HEX_LEN);
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
fn parse_hex_rejects_non_hex() {
    assert!(SessionId::parse_hex(&"g".repeat(32)).is_none());
    let mut almost = "a".repeat(31);
    almost.push('z');
    assert!(SessionId::parse_hex(&almost).is_none());
}

#[test]
fn parses_uppercase_and_normalises_to_lowercase_on_format() {
    let id = SessionId::parse_hex("0123456789ABCDEFFEDCBA9876543210").unwrap();
    assert_eq!(id.to_hex(), "0123456789abcdeffedcba9876543210");
}

#[test]
fn debug_output_is_truncated() {
    let id = SessionId::from_bytes([0xAB; 16]);
    let debug = format!("{id:?}");
    assert!(debug.starts_with("SessionId("));
    assert!(debug.contains("abababab"));
    // Do not expose the full ID in Debug output.
    assert!(!debug.contains(&id.to_hex()));
}

#[test]
fn random_ids_differ() {
    let rng = SystemRandom::new();
    let a = SessionId::random(&rng).unwrap();
    let b = SessionId::random(&rng).unwrap();
    assert_ne!(a, b, "two consecutive random session IDs must differ");
}
