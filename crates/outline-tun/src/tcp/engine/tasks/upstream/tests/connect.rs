use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{ConnectFailureCache, build_direct_dial_candidates};

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

#[test]
fn connect_cache_recently_failed_within_ttl_then_expires() {
    let t0 = Instant::now();
    let mut c = ConnectFailureCache::new(Duration::from_secs(4), 1024);
    let a = addr("1.2.3.4:443");
    assert!(!c.recently_failed(&a, t0), "not failed before any record");
    c.record_failure(a, t0);
    assert!(c.recently_failed(&a, t0 + Duration::from_secs(3)), "within TTL -> fail-fast");
    assert!(!c.recently_failed(&a, t0 + Duration::from_secs(5)), "past TTL -> dial again");
}

#[test]
fn connect_cache_cleared_on_success() {
    let t0 = Instant::now();
    let mut c = ConnectFailureCache::new(Duration::from_secs(4), 1024);
    let a = addr("1.2.3.4:443");
    c.record_failure(a, t0);
    assert!(c.recently_failed(&a, t0));
    c.clear(&a); // a later successful connect clears the negative entry
    assert!(!c.recently_failed(&a, t0));
}

#[test]
fn connect_cache_is_bounded_at_cap() {
    let t0 = Instant::now();
    let mut c = ConnectFailureCache::new(Duration::from_secs(4), 2);
    // 5 distinct same-time failures into a cap-2 cache: nothing expired to sweep,
    // so it must stop growing at the cap rather than accumulate unbounded.
    for i in 0..5u16 {
        c.record_failure(addr(&format!("10.0.0.1:{}", 1000 + i)), t0);
    }
    let live = (0..5u16)
        .filter(|i| c.recently_failed(&addr(&format!("10.0.0.1:{}", 1000 + i)), t0))
        .count();
    assert!(live <= 2, "cache exceeded cap: {live} live entries");
}

#[test]
fn connect_cache_sweeps_expired_to_admit_new() {
    let t0 = Instant::now();
    let mut c = ConnectFailureCache::new(Duration::from_secs(4), 2);
    c.record_failure(addr("10.0.0.1:1"), t0);
    c.record_failure(addr("10.0.0.1:2"), t0);
    // After TTL, a new failure sweeps the two expired entries and is admitted.
    let later = t0 + Duration::from_secs(5);
    c.record_failure(addr("10.0.0.1:3"), later);
    assert!(
        c.recently_failed(&addr("10.0.0.1:3"), later),
        "fresh entry admitted after sweep"
    );
    assert!(!c.recently_failed(&addr("10.0.0.1:1"), later), "expired entry gone");
}
