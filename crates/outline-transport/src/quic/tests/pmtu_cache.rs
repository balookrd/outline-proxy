use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use super::super::vendored::FirstProbe;
use super::*;

const TTL: Duration = Duration::from_secs(3 * 24 * 3600);

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pmtu-{name}-{}-{nanos}", std::process::id()))
}

#[test]
fn missing_entry_has_no_hint() {
    let cache = PmtuCache::new(None, TTL);
    assert_eq!(cache.hint("a:443|fw=-|net=0", SystemTime::now()), None);
}

const HOUR: Duration = Duration::from_secs(3600);
const SEED_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

#[test]
fn upper_bound_value_is_the_hint_until_the_long_ttl_expires() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_452, t0));
    assert_eq!(cache.hint("k", t0 + HOUR), Some(FirstProbe::capped(1_452)));
    assert_eq!(
        cache.hint("k", t0 + TTL - Duration::from_secs(1)),
        Some(FirstProbe::capped(1_452))
    );
    assert_eq!(cache.hint("k", t0 + TTL), Some(FirstProbe::seed(1_452)));
}

#[test]
fn value_below_the_upper_bound_expires_after_an_hour() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_448, t0));
    assert_eq!(
        cache.hint("k", t0 + HOUR - Duration::from_secs(1)),
        Some(FirstProbe::capped(1_448))
    );
    assert_eq!(cache.hint("k", t0 + HOUR), Some(FirstProbe::seed(1_448)));
}

#[test]
fn same_value_does_not_refresh_the_entry() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_452, t0));
    assert!(!cache.record("k", 1_452, t0 + HOUR));
    assert_eq!(
        cache.hint("k", t0 + TTL),
        Some(FirstProbe::seed(1_452)),
        "TTL counts from the first confirmation"
    );
}

#[test]
fn low_value_is_re_searched_an_hour_after_it_was_first_stored() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_417, t0));
    assert!(!cache.record("k", 1_417, t0 + Duration::from_secs(1800)));
    assert_eq!(
        cache.hint("k", t0 + HOUR),
        Some(FirstProbe::seed(1_417)),
        "TTL counts from the first confirmation"
    );
    assert!(
        cache.record("k", 1_417, t0 + HOUR),
        "a seeded connection stores an expired entry afresh"
    );
}

#[test]
fn recorder_skips_a_connection_that_settled_at_its_capping_first_probe() {
    assert!(!should_record(Some(FirstProbe::capped(1_417)), 1_417));
    assert!(!should_record(Some(FirstProbe::capped(1_452)), 1_452));
}

#[test]
fn recorder_stores_full_searches_seeds_and_changed_results() {
    assert!(should_record(None, 1_417), "no hint means a full search");
    assert!(should_record(Some(FirstProbe::capped(1_452)), 1_448), "the path shrank");
    assert!(should_record(Some(FirstProbe::capped(1_417)), 1_400), "the hint was clamped");
    assert!(
        should_record(Some(FirstProbe::seed(1_448)), 1_448),
        "a seed searched above itself, so settling there is a real observation"
    );
}

#[test]
fn expired_entry_is_a_seed_until_the_seed_age_limit() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    assert!(cache.record("k", 1_448, t0));
    assert_eq!(cache.hint("k", t0 + HOUR), Some(FirstProbe::seed(1_448)));
    assert_eq!(
        cache.hint("k", t0 + SEED_MAX_AGE - Duration::from_secs(1)),
        Some(FirstProbe::seed(1_448))
    );
    assert_eq!(cache.hint("k", t0 + SEED_MAX_AGE), None, "too old to seed");
}

#[test]
fn seeded_result_restarts_the_capped_hour() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let t1 = t0 + HOUR + Duration::from_secs(5);
    assert!(cache.record("k", 1_448, t0));
    assert_eq!(cache.hint("k", t1), Some(FirstProbe::seed(1_448)));
    assert!(cache.record("k", 1_448, t1), "the expired entry is stored afresh");
    assert_eq!(cache.hint("k", t1 + Duration::from_secs(1)), Some(FirstProbe::capped(1_448)));
    assert_eq!(cache.hint("k", t1 + HOUR), Some(FirstProbe::seed(1_448)));
}

#[test]
fn ttl_class_follows_the_stored_value_across_changes() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let t1 = t0 + Duration::from_secs(100);
    let t2 = t1 + Duration::from_secs(100);
    assert!(cache.record("k", 1_452, t0));
    assert!(cache.record("k", 1_448, t1), "1452 -> 1448 resets confirmed_at");
    assert_eq!(
        cache.hint("k", t1 + HOUR - Duration::from_secs(1)),
        Some(FirstProbe::capped(1_448))
    );
    assert_eq!(
        cache.hint("k", t1 + HOUR),
        Some(FirstProbe::seed(1_448)),
        "1448 expires an hour after t1"
    );
    assert!(cache.record("k", 1_452, t2), "1448 -> 1452 resets confirmed_at again");
    assert_eq!(
        cache.hint("k", t2 + HOUR),
        Some(FirstProbe::capped(1_452)),
        "back in the long class"
    );
    assert_eq!(
        cache.hint("k", t2 + TTL - Duration::from_secs(1)),
        Some(FirstProbe::capped(1_452))
    );
    assert_eq!(cache.hint("k", t2 + TTL), Some(FirstProbe::seed(1_452)));
}

#[test]
fn changed_value_replaces_the_entry() {
    let cache = PmtuCache::new(None, TTL);
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    cache.record("k", 1_448, t0);
    assert!(cache.record("k", 1_439, t0 + Duration::from_secs(10)));
    assert_eq!(cache.hint("k", t0 + Duration::from_secs(20)), Some(FirstProbe::capped(1_439)));
}

#[test]
fn entries_survive_a_restart() {
    let path = temp_path("roundtrip");
    let now = SystemTime::now();
    let cache = PmtuCache::new(Some(path.clone()), TTL);
    cache.record("host:443|fw=-|net=00000000deadbeef", 1_448, now);
    cache.flush().unwrap();

    let reloaded = PmtuCache::new(Some(path.clone()), TTL);
    assert_eq!(
        reloaded.hint("host:443|fw=-|net=00000000deadbeef", now),
        Some(FirstProbe::capped(1_448))
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn corrupt_lines_are_skipped() {
    let path = temp_path("corrupt");
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(&path, format!("garbage\nk\t1448\t{now}\nk2\tnot-a-number\t1\n")).unwrap();
    let cache = PmtuCache::new(Some(path.clone()), TTL);
    assert_eq!(cache.hint("k", SystemTime::now()), Some(FirstProbe::capped(1_448)));
    assert_eq!(cache.hint("k2", SystemTime::now()), None);
    let _ = std::fs::remove_file(path);
}

#[test]
fn values_outside_the_quic_range_are_rejected() {
    let cache = PmtuCache::new(None, TTL);
    let now = SystemTime::now();
    assert!(!cache.record("k", 1_199, now));
    assert!(!cache.record("k", 1_453, now));
    assert_eq!(cache.hint("k", now), None);
}

#[test]
fn network_hash_differs_between_networks_and_is_stable() {
    let wifi = network_hash(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 23)));
    let lte = network_hash(IpAddr::V4(Ipv4Addr::new(10, 64, 12, 7)));
    assert_ne!(wifi, lte);
    assert_eq!(wifi, network_hash(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 23))));
}

#[test]
fn key_string_hides_the_local_address() {
    let key = PmtuKey {
        server: "example.com".into(),
        port: 443,
        fwmark: Some(18),
        net: 0xdead_beef,
    };
    assert_eq!(key.as_str(), "example.com:443|fw=18|net=00000000deadbeef");
}
