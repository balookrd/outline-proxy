use super::{MAX_DETAIL_CARDINALITY, intern_detail, normalize_detail_string};

#[test]
fn normalize_replaces_digits_and_special_chars() {
    let result = normalize_detail_string("connect to 192.168.1.1:8080 failed");
    assert!(!result.chars().any(|c| c.is_ascii_digit()));
    assert!(result.len() <= 48);
}

#[test]
fn normalize_trims_leading_trailing_underscores() {
    let result = normalize_detail_string("!!!error!!!");
    assert!(!result.starts_with('_') && !result.ends_with('_'));
}

/// intern_detail must return only valid metric label strings (ASCII
/// alphanumeric + underscore) regardless of what the global pool contains.
#[test]
fn intern_detail_output_is_always_a_valid_metric_label() {
    // Feed more values than the cap to guarantee we exercise both the
    // normal and the overflow path, no matter how many other tests have
    // already populated the shared pool.
    for i in 0..MAX_DETAIL_CARDINALITY + 10 {
        let input = format!("intern_label_test_probe_{i:04}");
        let out = intern_detail(input);
        assert!(!out.is_empty(), "output must be non-empty");
        assert!(
            out.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "output must be a valid metric label, got: {out:?}"
        );
    }
}

/// Once a value has been interned it must be returned unchanged on
/// subsequent calls (idempotent).  This holds whether the value was
/// inserted on first call or was already in the pool from a prior call.
#[test]
fn intern_detail_is_idempotent_for_already_seen_values() {
    let known = "idempotency_probe_value";
    let first = intern_detail(known.to_string());
    let second = intern_detail(known.to_string());
    // Both calls must return the same string (either the value itself
    // or "other_overflow" — but consistently the same).
    assert_eq!(first, second);
}
