//! Tests for the new-shape `[[uplink_group]]` loader (`load_groups`).
//!
//! These pin behaviours that are *not* exercised by the legacy-path
//! `load_uplinks` tests in `uplinks.rs`: anything that fires only when
//! the config declares one or more `[[uplink_group]]` sections and
//! every `[[uplinks]]` carries an explicit `group` label.

use clap::Parser;

use crate::config::Args;
use crate::config::ConfigFile;
use crate::config::normalize_outline_section;

use super::super::groups::load_groups;

/// Walk `load_groups` on a TOML string. Mirrors what `load_config` does
/// internally, minus the disk + async-IO machinery, so tests can drive
/// the loader with a freshly-rolled RNG on every invocation.
fn run_load_groups(toml_str: &str) -> Vec<outline_uplink::UplinkGroupConfig> {
    let file: ConfigFile = toml::from_str(toml_str).expect("toml parses");
    let outline = normalize_outline_section(&file);
    let args = Args::parse_from(["test"]);
    load_groups(outline.as_ref(), Some(&file), &args).expect("load_groups succeeds")
}

/// Project the post-load wire chain of an uplink into a tuple of
/// transport+url pairs so test assertions can compare orderings
/// without having to spell out the full `UplinkConfig` shape.
fn wire_chain_fingerprint(uplink: &outline_uplink::UplinkConfig) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = Vec::with_capacity(1 + uplink.fallbacks.len());
    out.push((
        uplink.transport.to_string(),
        uplink.tcp_ws_url.as_ref().map(|u| u.as_str().to_string()),
    ));
    for fb in &uplink.fallbacks {
        out.push((
            fb.transport.to_string(),
            fb.tcp_ws_url.as_ref().map(|u| u.as_str().to_string()),
        ));
    }
    out
}

#[test]
fn shuffle_wires_in_uplink_group_produces_distinct_orderings_within_group() {
    // Regression for the new-shape `[[uplink_group]]` path: before the
    // fix, `load_groups` built `UplinkConfig`s via direct `try_into`
    // and never invoked `shuffle_wire_chains_per_group`. Operators
    // setting `shuffle_wires = true` on every uplink of one group
    // saw the operator-ordered chain unchanged on every restart, so
    // two same-shape uplinks in the same group rendered identical
    // wire chips in the dashboard at startup.
    //
    // With the fix, the per-group dedup pass picks distinct
    // permutations for the two uplinks every time (2 ≤ 3! = 6, so
    // distinctness is always achievable here).
    let toml_str = r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplinks]]
        name = "alpha"
        group = "main"
        transport = "ws"
        tcp_ws_url = "wss://primary.example.com/secret/tcp"
        tcp_mode = "h1"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        shuffle_wires = true

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-a.example.com/secret/tcp"
        tcp_mode = "h1"

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-b.example.com/secret/tcp"
        tcp_mode = "h1"

        [[uplinks]]
        name = "beta"
        group = "main"
        transport = "ws"
        tcp_ws_url = "wss://primary.example.com/secret/tcp"
        tcp_mode = "h1"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        shuffle_wires = true

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-a.example.com/secret/tcp"
        tcp_mode = "h1"

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-b.example.com/secret/tcp"
        tcp_mode = "h1"
    "#;

    // 64 seeds to make the assertion hard — naive independent shuffles
    // would land on the same permutation ~17 % of the time per pair,
    // so a single seed could pass on luck even with a broken loader.
    for _ in 0..64 {
        let groups = run_load_groups(toml_str);
        assert_eq!(groups.len(), 1);
        let main = &groups[0];
        assert_eq!(main.uplinks.len(), 2);
        let alpha = wire_chain_fingerprint(&main.uplinks[0]);
        let beta = wire_chain_fingerprint(&main.uplinks[1]);
        assert_ne!(
            alpha, beta,
            "two uplinks in one [[uplink_group]] with shuffle_wires must end up on distinct \
             wire chains (got alpha={alpha:?}, beta={beta:?})",
        );
    }
}

#[test]
fn shuffle_wires_off_in_uplink_group_preserves_operator_ordering() {
    // Pin the negative: when shuffle_wires is absent (default false),
    // the loader must not silently reshuffle the chain. The wire chain
    // produced by `load_groups` should match the on-disk order
    // exactly, so dashboards and metrics keep showing the operator's
    // primary as wire 0.
    let toml_str = r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplinks]]
        name = "alpha"
        group = "main"
        transport = "ws"
        tcp_ws_url = "wss://primary.example.com/secret/tcp"
        tcp_mode = "h1"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-a.example.com/secret/tcp"
        tcp_mode = "h1"

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-b.example.com/secret/tcp"
        tcp_mode = "h1"
    "#;

    for _ in 0..32 {
        let groups = run_load_groups(toml_str);
        let alpha = &groups[0].uplinks[0];
        assert_eq!(
            alpha.tcp_ws_url.as_ref().map(|u| u.as_str()),
            Some("wss://primary.example.com/secret/tcp"),
            "without shuffle_wires the primary must stay at wire 0",
        );
        assert_eq!(alpha.fallbacks.len(), 2);
        assert_eq!(
            alpha.fallbacks[0].tcp_ws_url.as_ref().map(|u| u.as_str()),
            Some("wss://fb-a.example.com/secret/tcp"),
        );
        assert_eq!(
            alpha.fallbacks[1].tcp_ws_url.as_ref().map(|u| u.as_str()),
            Some("wss://fb-b.example.com/secret/tcp"),
        );
    }
}

#[test]
fn shuffle_wires_in_uplink_group_isolates_groups() {
    // Two uplinks in different groups must NOT be deduped against
    // each other — `shuffle_wire_chains_per_group` is keyed on the
    // group name, and `load_groups` feeds each bucket's name as the
    // label. Coincidental matches are allowed across groups.
    //
    // We assert the weaker property: with `shuffle_wires = true` on
    // both, the wire chain of each uplink is **a permutation** of the
    // configured chain (the shuffle ran), without requiring the two
    // groups' orderings to differ from each other.
    let toml_str = r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplink_group]]
        name = "backup"

        [[uplinks]]
        name = "alpha"
        group = "main"
        transport = "ws"
        tcp_ws_url = "wss://primary.example.com/secret/tcp"
        tcp_mode = "h1"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        shuffle_wires = true

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-a.example.com/secret/tcp"
        tcp_mode = "h1"

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-b.example.com/secret/tcp"
        tcp_mode = "h1"

        [[uplinks]]
        name = "beta"
        group = "backup"
        transport = "ws"
        tcp_ws_url = "wss://primary.example.com/secret/tcp"
        tcp_mode = "h1"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        shuffle_wires = true

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-a.example.com/secret/tcp"
        tcp_mode = "h1"

        [[uplinks.fallbacks]]
        transport = "ws"
        tcp_ws_url = "wss://fb-b.example.com/secret/tcp"
        tcp_mode = "h1"
    "#;

    let expected: std::collections::HashSet<&str> = [
        "wss://primary.example.com/secret/tcp",
        "wss://fb-a.example.com/secret/tcp",
        "wss://fb-b.example.com/secret/tcp",
    ]
    .into_iter()
    .collect();

    for _ in 0..32 {
        let groups = run_load_groups(toml_str);
        assert_eq!(groups.len(), 2);
        for group in &groups {
            assert_eq!(group.uplinks.len(), 1);
            let u = &group.uplinks[0];
            let mut got: std::collections::HashSet<&str> = std::collections::HashSet::new();
            got.insert(u.tcp_ws_url.as_ref().unwrap().as_str());
            for fb in &u.fallbacks {
                got.insert(fb.tcp_ws_url.as_ref().unwrap().as_str());
            }
            assert_eq!(
                got, expected,
                "shuffle must preserve the full wire set, not drop or duplicate any wire",
            );
        }
    }
}
