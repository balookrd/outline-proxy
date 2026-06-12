//! Tests for the XHTTP submode selector and session-id rules.

use super::{SESSION_ID_ALPHABET, XhttpSubmode, is_valid_session_id};

#[test]
fn absent_query_defaults_to_packet_up() {
    assert_eq!(XhttpSubmode::parse_query(None), XhttpSubmode::PacketUp);
    assert_eq!(XhttpSubmode::parse_query(Some("")), XhttpSubmode::PacketUp);
}

#[test]
fn dashed_and_underscored_stream_one_accepted() {
    assert_eq!(XhttpSubmode::parse_query(Some("mode=stream-one")), XhttpSubmode::StreamOne);
    assert_eq!(XhttpSubmode::parse_query(Some("mode=stream_one")), XhttpSubmode::StreamOne);
}

#[test]
fn unknown_mode_values_fall_back_to_packet_up() {
    assert_eq!(XhttpSubmode::parse_query(Some("mode=packet-up")), XhttpSubmode::PacketUp);
    assert_eq!(XhttpSubmode::parse_query(Some("mode=stream-up")), XhttpSubmode::PacketUp);
    assert_eq!(XhttpSubmode::parse_query(Some("mode=")), XhttpSubmode::PacketUp);
}

#[test]
fn mode_is_found_among_other_query_pairs() {
    assert_eq!(
        XhttpSubmode::parse_query(Some("a=b&mode=stream-one&c=d")),
        XhttpSubmode::StreamOne,
    );
    assert_eq!(XhttpSubmode::parse_query(Some("a=b&c=d")), XhttpSubmode::PacketUp);
}

#[test]
fn first_mode_pair_wins() {
    // Matches the historical behaviour on both sides: the scan stops
    // at the first `mode=` pair.
    assert_eq!(
        XhttpSubmode::parse_query(Some("mode=stream-one&mode=other")),
        XhttpSubmode::StreamOne,
    );
}

#[test]
fn wire_spelling_is_dashed() {
    assert_eq!(XhttpSubmode::PacketUp.as_wire_str(), "packet-up");
    assert_eq!(XhttpSubmode::StreamOne.as_wire_str(), "stream-one");
    assert_eq!(XhttpSubmode::StreamOne.to_string(), "stream-one");
    assert_eq!(XhttpSubmode::default(), XhttpSubmode::PacketUp);
}

#[test]
fn session_id_validation_contract() {
    assert!(is_valid_session_id("abcDEF123"));
    assert!(is_valid_session_id("a-b_c.d"));
    assert!(is_valid_session_id(&"x".repeat(128)));
    assert!(!is_valid_session_id(""));
    assert!(!is_valid_session_id(&"x".repeat(129)));
    assert!(!is_valid_session_id("with/slash"));
    assert!(!is_valid_session_id("with space"));
    assert!(!is_valid_session_id("кириллица"));
}

#[test]
fn alphabet_is_distinct_and_validates() {
    let unique: std::collections::BTreeSet<_> = SESSION_ID_ALPHABET.iter().collect();
    assert_eq!(unique.len(), SESSION_ID_ALPHABET.len());
    let all: String = SESSION_ID_ALPHABET.iter().map(|b| char::from(*b)).collect();
    assert!(is_valid_session_id(&all));
}
