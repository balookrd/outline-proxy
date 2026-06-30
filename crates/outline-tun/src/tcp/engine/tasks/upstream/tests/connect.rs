use std::net::SocketAddr;

use super::build_direct_dial_candidates;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn literal_appended_as_fallback_after_resolved() {
    let resolved = [addr("1.2.3.4:443"), addr("5.6.7.8:443")];
    let literal = Some(addr("9.9.9.9:443"));
    // Re-resolved addresses are tried first; the literal IP the client dialled
    // is the last-resort fallback so a dead re-resolve cannot black-hole it.
    assert_eq!(
        build_direct_dial_candidates(&resolved, literal),
        vec![addr("1.2.3.4:443"), addr("5.6.7.8:443"), addr("9.9.9.9:443")],
    );
}

#[test]
fn empty_resolve_falls_back_to_literal_only() {
    // SNI re-resolve returned nothing → dial the literal IP (what direct-by-IP
    // would have done). This is the Kinopoisk/AWS case: re-resolve dead, literal
    // reachable.
    assert_eq!(
        build_direct_dial_candidates(&[], Some(addr("9.9.9.9:443"))),
        vec![addr("9.9.9.9:443")],
    );
}

#[test]
fn literal_not_duplicated_when_already_resolved() {
    // If the resolver already returned the literal, do not dial it twice.
    let resolved = [addr("9.9.9.9:443")];
    assert_eq!(
        build_direct_dial_candidates(&resolved, Some(addr("9.9.9.9:443"))),
        vec![addr("9.9.9.9:443")],
    );
}

#[test]
fn no_literal_keeps_resolved_only() {
    let resolved = [addr("1.2.3.4:443")];
    assert_eq!(build_direct_dial_candidates(&resolved, None), vec![addr("1.2.3.4:443")]);
}

#[test]
fn empty_everything_yields_no_candidates() {
    assert!(build_direct_dial_candidates(&[], None).is_empty());
}
