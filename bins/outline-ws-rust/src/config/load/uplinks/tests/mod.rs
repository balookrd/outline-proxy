use super::parse_human_duration;
use std::time::Duration;

#[test]
fn plain_seconds() {
    assert_eq!(parse_human_duration("shuffle_timer", "60").unwrap(), Duration::from_secs(60));
}

#[test]
fn single_units() {
    assert_eq!(parse_human_duration("shuffle_timer", "45s").unwrap(), Duration::from_secs(45));
    assert_eq!(parse_human_duration("shuffle_timer", "5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_human_duration("shuffle_timer", "1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(
        parse_human_duration("shuffle_timer", "2d").unwrap(),
        Duration::from_secs(172_800)
    );
}

#[test]
fn compound_units() {
    assert_eq!(
        parse_human_duration("shuffle_timer", "1h30m").unwrap(),
        Duration::from_secs(5400)
    );
    assert_eq!(
        parse_human_duration("shuffle_timer", "2h15m30s").unwrap(),
        Duration::from_secs(8130)
    );
    assert_eq!(
        parse_human_duration("shuffle_timer", "1d6h").unwrap(),
        Duration::from_secs(108_000)
    );
}

#[test]
fn whitespace_ignored() {
    assert_eq!(
        parse_human_duration("shuffle_timer", " 1h 30m ").unwrap(),
        Duration::from_secs(5400)
    );
}

#[test]
fn rejects_empty() {
    assert!(parse_human_duration("shuffle_timer", "").is_err());
    assert!(parse_human_duration("shuffle_timer", "   ").is_err());
}

#[test]
fn rejects_zero() {
    assert!(parse_human_duration("shuffle_timer", "0").is_err());
    assert!(parse_human_duration("shuffle_timer", "0s").is_err());
    assert!(parse_human_duration("shuffle_timer", "0h0m").is_err());
}

#[test]
fn rejects_unknown_unit() {
    assert!(parse_human_duration("shuffle_timer", "5y").is_err());
    assert!(parse_human_duration("shuffle_timer", "3 weeks").is_err());
}

#[test]
fn rejects_repeated_unit() {
    assert!(parse_human_duration("shuffle_timer", "1h2h").is_err());
}

#[test]
fn rejects_trailing_number() {
    assert!(parse_human_duration("shuffle_timer", "1h30").is_err());
}

#[test]
fn rejects_unit_without_number() {
    assert!(parse_human_duration("shuffle_timer", "hm").is_err());
}
