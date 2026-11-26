//! Tests for the XHTTP submode selector and session-id rules.

use super::{
    PADDING_HEADER, PADDING_MAX_LEN, PADDING_MIN_LEN, SESSION_ID_ALPHABET, SsPathKind,
    UDP_RECORDS_HEADER, XhttpSubmode, decode_kind, encode_kind_first_byte, generate_padding_header,
    header_flag_enabled, is_valid_session_id, masquerade_response_headers, post_response_headers,
};

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

#[test]
fn kind_bit_round_trips_for_every_random_byte() {
    // The encode side maps an arbitrary random byte to a first character;
    // the decode side must recover the same kind from that character for
    // all 256 byte values and both kinds.
    for kind in [SsPathKind::Tcp, SsPathKind::Udp] {
        for rand_byte in 0..=u8::MAX {
            let first = encode_kind_first_byte(rand_byte, kind);
            // Stays inside the generation alphabet, so the whole id validates.
            assert!(SESSION_ID_ALPHABET.contains(&first), "first char must be alphanumeric");
            let token = format!("{}restofid", char::from(first));
            assert!(is_valid_session_id(&token));
            assert_eq!(decode_kind(&token), kind, "byte {rand_byte} kind {kind:?}");
        }
    }
}

#[test]
fn encoded_first_chars_stay_uniform_per_parity() {
    // Each kind must be able to reach all 31 characters of its parity, so
    // the marker does not collapse the first char onto a tell-tale subset.
    for kind in [SsPathKind::Tcp, SsPathKind::Udp] {
        let reached: std::collections::BTreeSet<u8> =
            (0..=u8::MAX).map(|b| encode_kind_first_byte(b, kind)).collect();
        assert_eq!(reached.len(), 31, "kind {kind:?} should reach 31 first chars");
    }
    // TCP and UDP first chars never overlap (disjoint parities).
    let tcp: std::collections::BTreeSet<u8> = (0..=u8::MAX)
        .map(|b| encode_kind_first_byte(b, SsPathKind::Tcp))
        .collect();
    let udp: std::collections::BTreeSet<u8> = (0..=u8::MAX)
        .map(|b| encode_kind_first_byte(b, SsPathKind::Udp))
        .collect();
    assert!(tcp.is_disjoint(&udp));
    // Together they cover the entire alphabet.
    assert_eq!(tcp.len() + udp.len(), SESSION_ID_ALPHABET.len());
}

#[test]
fn decode_defaults_to_tcp_for_non_alphabet_or_empty() {
    // Empty, or a first character the alphabet does not contain (still
    // valid per is_valid_session_id), falls back to TCP — the safe default
    // so a stray / third-party id never lands on the UDP relay.
    assert_eq!(decode_kind(""), SsPathKind::Tcp);
    assert_eq!(decode_kind("-abc"), SsPathKind::Tcp);
    assert_eq!(decode_kind("_x"), SsPathKind::Tcp);
    assert_eq!(decode_kind(".y"), SsPathKind::Tcp);
    // 'A' is index 0 (even) → TCP; 'B' is index 1 (odd) → UDP.
    assert_eq!(decode_kind("Axxxx"), SsPathKind::Tcp);
    assert_eq!(decode_kind("Bxxxx"), SsPathKind::Udp);
}

#[test]
fn kind_labels() {
    assert_eq!(SsPathKind::Tcp.as_str(), "tcp");
    assert_eq!(SsPathKind::Udp.as_str(), "udp");
}

#[test]
fn generate_padding_header_respects_bounds_and_alphabet() {
    let mut rng = rand::rng();
    for _ in 0..64 {
        let (name, value) = generate_padding_header(&mut rng);
        assert_eq!(name.as_str(), PADDING_HEADER);
        let s = value.to_str().unwrap();
        assert!(
            (PADDING_MIN_LEN..=PADDING_MAX_LEN).contains(&s.len()),
            "unexpected X-Padding length {}",
            s.len()
        );
        assert!(s.bytes().all(|b| SESSION_ID_ALPHABET.contains(&b)));
    }
}

#[test]
fn response_header_sets_and_flag_helper() {
    assert_eq!(masquerade_response_headers().len(), 4);
    assert_eq!(post_response_headers().len(), 2);
    let mut map = http::HeaderMap::new();
    assert!(!header_flag_enabled(&map, UDP_RECORDS_HEADER));
    map.insert(UDP_RECORDS_HEADER, http::HeaderValue::from_static(" 1 "));
    assert!(header_flag_enabled(&map, UDP_RECORDS_HEADER));
}
