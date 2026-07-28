use super::*;

fn section(toml_str: &str) -> LoadBalancingSection {
    toml::from_str(toml_str).expect("valid section TOML")
}

#[test]
fn reselect_at_parses_sorts_and_dedups() {
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_at = ["10:10", "03:00", "10:10"]
    "#,
    );
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert_eq!(config.reselect_at, vec![(3, 0), (10, 10)]);
    assert_eq!(config.reselect_interval, None);
}

#[test]
fn reselect_interval_parses_human_duration() {
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_interval = "10h"
    "#,
    );
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert_eq!(config.reselect_interval, Some(Duration::from_secs(36_000)));
    assert!(config.reselect_at.is_empty());
}

#[test]
fn reselect_keys_are_mutually_exclusive() {
    let lb = section(
        r#"
        mode = "active_passive"
        reselect_at = ["03:00"]
        reselect_interval = "10h"
    "#,
    );
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("mutually exclusive"), "{err}");
}

#[test]
fn reselect_requires_active_passive() {
    let lb = section(r#"reselect_at = ["03:00"]"#); // mode defaults to active_active
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("active_passive"), "{err}");
}

#[test]
fn reselect_requires_strict_routing_scope() {
    // mode is active_passive, but routing_scope defaults to per_flow, which
    // has no single strict active slot to rotate — this must be rejected the
    // same way an active_active mode is.
    let lb = section(
        r#"
        mode = "active_passive"
        reselect_at = ["03:00"]
    "#,
    );
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("routing_scope"), "{err}");
}

#[test]
fn reselect_accepts_global_or_per_uplink_scope() {
    for scope in ["global", "per_uplink"] {
        let lb = section(&format!(
            "mode = \"active_passive\"\nrouting_scope = \"{scope}\"\nreselect_at = [\"03:00\"]"
        ));
        assert!(
            load_balancing_config(Some(&lb)).is_ok(),
            "routing_scope = \"{scope}\" must be accepted alongside reselect_at"
        );
    }
}

#[test]
fn reselect_interval_rejects_below_one_minute() {
    // "10" is bare-seconds (one character off the documented "10h") and, off
    // a cluster, would RST every in-flight SOCKS5 TCP session every 10s.
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_interval = "10"
    "#,
    );
    let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
    assert!(err.contains("reselect_interval"), "{err}");
    assert!(err.contains("60"), "{err}");
}

#[test]
fn reselect_interval_accepts_the_one_minute_bound_and_above() {
    for value in ["60s", "1m", "10h"] {
        let lb = section(&format!(
            "mode = \"active_passive\"\nrouting_scope = \"global\"\nreselect_interval = \"{value}\""
        ));
        assert!(
            load_balancing_config(Some(&lb)).is_ok(),
            "reselect_interval = \"{value}\" must be accepted"
        );
    }
}

#[test]
fn reselect_interval_accepts_a_bare_integer_as_seconds() {
    // `reselect_interval` shares `parse_human_duration` with `shuffle_timer`,
    // which still reads a bare integer as seconds. The docs only recommend
    // the unit-suffixed form (a bare integer is one typo away from the 60s
    // floor), but the loader must not reject syntax the shared parser
    // otherwise accepts — pin that a bare integer at/above the bound still
    // parses as seconds.
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_interval = "300"
    "#,
    );
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert_eq!(config.reselect_interval, Some(Duration::from_secs(300)));
}

#[test]
fn reselect_at_rejects_malformed_entries() {
    // Each case pins which of the three `parse_wall_clock` rejection paths
    // fires, distinguished by a substring unique to that `bail!` branch —
    // `is_err()` alone would not catch the three branches collapsing into
    // one wrong reason.
    let cases: &[(&str, &str)] = &[
        ("3", "must be \"HH:MM\""), // missing colon
        ("", "must be \"HH:MM\""),  // missing colon (empty entry)
        ("aa:bb", "invalid hours"), // non-digit component
        ("24:00", "out of range"),  // hour out of range
        ("03:60", "out of range"),  // minute out of range
    ];
    for (bad, expected_substr) in cases {
        let lb = section(&format!(
            "mode = \"active_passive\"\nrouting_scope = \"global\"\nreselect_at = [\"{bad}\"]"
        ));
        let err = load_balancing_config(Some(&lb)).unwrap_err().to_string();
        assert!(err.contains(expected_substr), "input {bad:?}: got {err}");
    }
}

#[test]
fn reselect_at_accepts_boundary_values() {
    let lb = section(
        r#"
        mode = "active_passive"
        routing_scope = "global"
        reselect_at = ["23:59", "00:00"]
    "#,
    );
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert_eq!(config.reselect_at, vec![(0, 0), (23, 59)]);
}

#[test]
fn reselect_at_empty_list_is_disabled_not_an_error() {
    // `reselect_at = []` must be a no-op — mode defaults to active_active
    // here, so this also pins that an empty list does not trip the
    // active_passive requirement (unlike a non-empty one would).
    let lb = section(r#"reselect_at = []"#);
    let config = load_balancing_config(Some(&lb)).unwrap();
    assert!(config.reselect_at.is_empty());
    assert_eq!(config.reselect_interval, None);
}
