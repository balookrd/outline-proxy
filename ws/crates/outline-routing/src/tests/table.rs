use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::*;

fn v4(a: u8, b: u8, c: u8, d: u8) -> TargetAddr {
    TargetAddr::IpV4(Ipv4Addr::new(a, b, c, d), 80)
}

fn v6(s: &str) -> TargetAddr {
    TargetAddr::IpV6(s.parse::<Ipv6Addr>().unwrap(), 80)
}

fn rule(prefixes: &[&str], target: RouteTarget, fallback: Option<RouteTarget>) -> RouteRule {
    RouteRule {
        inline_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
        files: Vec::new(),
        file_poll: Duration::from_secs(60),
        target,
        fallback,
        invert: false,
    }
}

fn inverted_rule(
    prefixes: &[&str],
    target: RouteTarget,
    fallback: Option<RouteTarget>,
) -> RouteRule {
    RouteRule {
        inline_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
        files: Vec::new(),
        file_poll: Duration::from_secs(60),
        target,
        fallback,
        invert: true,
    }
}

#[tokio::test]
async fn resolve_first_match_wins() {
    let cfg = RoutingTableConfig {
        rules: vec![
            rule(&["10.0.0.0/8"], RouteTarget::Direct, None),
            rule(&["1.0.0.0/8"], RouteTarget::Group("main".into()), None),
        ],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    let d = table.resolve(&v4(10, 1, 2, 3)).await;
    assert_eq!(d.primary, RouteTarget::Direct);

    let d = table.resolve(&v4(1, 1, 1, 1)).await;
    assert_eq!(d.primary, RouteTarget::Group("main".into()));

    // Unmatched → default
    let d = table.resolve(&v4(8, 8, 8, 8)).await;
    assert_eq!(d.primary, RouteTarget::Group("main".into()));
}

#[tokio::test]
async fn resolve_carries_fallback() {
    let cfg = RoutingTableConfig {
        rules: vec![rule(
            &["1.0.0.0/8"],
            RouteTarget::Group("main".into()),
            Some(RouteTarget::Group("backup".into())),
        )],
        default_target: RouteTarget::Direct,
        default_fallback: Some(RouteTarget::Drop),
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    let d = table.resolve(&v4(1, 2, 3, 4)).await;
    assert_eq!(d.primary, RouteTarget::Group("main".into()));
    assert_eq!(d.fallback, Some(RouteTarget::Group("backup".into())));

    let d = table.resolve(&v4(9, 9, 9, 9)).await;
    assert_eq!(d.primary, RouteTarget::Direct);
    assert_eq!(d.fallback, Some(RouteTarget::Drop));
}

#[tokio::test]
async fn resolve_v6_and_domain_fallthrough() {
    let cfg = RoutingTableConfig {
        rules: vec![rule(&["fc00::/7"], RouteTarget::Direct, None)],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    assert_eq!(table.resolve(&v6("fc00::1")).await.primary, RouteTarget::Direct);
    assert_eq!(
        table.resolve(&v6("2001:db8::1")).await.primary,
        RouteTarget::Group("main".into())
    );
    // Domains never match a CIDR rule.
    let dom = TargetAddr::Domain("example.com".into(), 80);
    assert_eq!(table.resolve(&dom).await.primary, RouteTarget::Group("main".into()));
}

#[tokio::test]
async fn version_starts_at_zero_and_bumps() {
    let cfg = RoutingTableConfig {
        rules: vec![rule(&["1.0.0.0/8"], RouteTarget::Direct, None)],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();
    assert_eq!(table.version(), 0);
    table.version.fetch_add(1, Ordering::AcqRel);
    assert_eq!(table.version(), 1);
}

#[tokio::test]
async fn resolve_empty_rules_uses_default() {
    let cfg = RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Direct,
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();
    assert_eq!(table.resolve(&v4(1, 2, 3, 4)).await.primary, RouteTarget::Direct);
}

#[tokio::test]
async fn inverted_rule_matches_addresses_not_in_set() {
    // "tunnel only 1.0.0.0/8, everything else goes direct"
    let cfg = RoutingTableConfig {
        rules: vec![inverted_rule(
            &["1.0.0.0/8"],
            RouteTarget::Direct,
            None,
        )],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    // 8.8.8.8 is NOT in 1.0.0.0/8 → inverted rule matches → Direct
    assert_eq!(table.resolve(&v4(8, 8, 8, 8)).await.primary, RouteTarget::Direct);

    // 1.2.3.4 IS in 1.0.0.0/8 → inverted rule does NOT match → falls to default
    assert_eq!(
        table.resolve(&v4(1, 2, 3, 4)).await.primary,
        RouteTarget::Group("main".into())
    );
}

#[tokio::test]
async fn inverted_rule_does_not_match_domains() {
    let cfg = RoutingTableConfig {
        rules: vec![inverted_rule(
            &["10.0.0.0/8"],
            RouteTarget::Direct,
            None,
        )],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    // Domain targets skip all CIDR rules (even inverted ones).
    let dom = TargetAddr::Domain("example.com".into(), 80);
    assert_eq!(
        table.resolve(&dom).await.primary,
        RouteTarget::Group("main".into())
    );
}

/// Test that `spawn_route_watchers` reloads a file-backed CIDR set when
/// the file changes on disk and bumps `RoutingTable::version`.
///
/// Note: relies on the OS updating file mtime on write.  On APFS and ext4
/// (nanosecond resolution) this is always reliable; on HFS+ (1-second
/// resolution) there is a small chance of a false no-change if the write
/// happens in the same 1-second bucket as the initial compile.  The test
/// mitigates this by sleeping one full poll cycle (50 ms > file_poll =
/// 30 ms) before the re-write so the watcher seeds its mtime first.
#[tokio::test]
async fn watcher_reloads_cidr_file_and_bumps_version() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let tmp = std::env::temp_dir().join(format!(
        "outline_route_watcher_test_{}.txt",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos()
    ));

    // Initial content: 1.0.0.0/8
    tokio::fs::write(&tmp, b"1.0.0.0/8\n").await.unwrap();

    let cfg = RoutingTableConfig {
        rules: vec![RouteRule {
            inline_prefixes: vec![],
            files: vec![tmp.clone()],
            file_poll: Duration::from_millis(30),
            target: RouteTarget::Direct,
            fallback: None,
            invert: false,
        }],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = std::sync::Arc::new(RoutingTable::compile(&cfg).await.unwrap());
    assert_eq!(table.version(), 0, "version must start at 0");

    // Initial routing: 1.x.x.x → Direct, anything else → main
    assert_eq!(table.resolve(&v4(1, 2, 3, 4)).await.primary, RouteTarget::Direct);
    assert_eq!(
        table.resolve(&v4(2, 2, 2, 2)).await.primary,
        RouteTarget::Group("main".into())
    );

    spawn_route_watchers(std::sync::Arc::clone(&table));

    // Let the watcher task start and seed its initial mtime (one poll cycle).
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Change the prefix file to 2.0.0.0/8 — mtime is updated by the OS on write.
    tokio::fs::write(&tmp, b"2.0.0.0/8\n").await.unwrap();

    // Poll until the watcher fires (up to 2 s).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        tokio::time::sleep(Duration::from_millis(30)).await;
        if table.version() >= 1 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = tokio::fs::remove_file(&tmp).await;
            panic!("watcher did not reload the CIDR file within 2 s");
        }
    }
    assert_eq!(table.version(), 1);

    // After reload: 2.x.x.x → Direct, 1.x.x.x falls through to default (main)
    assert_eq!(table.resolve(&v4(2, 2, 2, 2)).await.primary, RouteTarget::Direct);
    assert_eq!(
        table.resolve(&v4(1, 2, 3, 4)).await.primary,
        RouteTarget::Group("main".into())
    );

    let _ = tokio::fs::remove_file(&tmp).await;
}

#[tokio::test]
async fn inverted_and_normal_rules_coexist() {
    let cfg = RoutingTableConfig {
        rules: vec![
            // First: RFC1918 → direct (normal)
            rule(&["10.0.0.0/8", "192.168.0.0/16"], RouteTarget::Direct, None),
            // Second: everything NOT in RU list → tunnel via main (inverted)
            inverted_rule(
                &["5.0.0.0/8"],
                RouteTarget::Group("main".into()),
                None,
            ),
        ],
        default_target: RouteTarget::Group("backup".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();

    // 10.1.1.1 → normal rule matches → Direct
    assert_eq!(table.resolve(&v4(10, 1, 1, 1)).await.primary, RouteTarget::Direct);

    // 8.8.8.8 → not RFC1918 (skip rule 1), not in 5.0.0.0/8 → inverted matches → main
    assert_eq!(
        table.resolve(&v4(8, 8, 8, 8)).await.primary,
        RouteTarget::Group("main".into())
    );

    // 5.1.2.3 → not RFC1918 (skip rule 1), IS in 5.0.0.0/8 → inverted doesn't match → default
    assert_eq!(
        table.resolve(&v4(5, 1, 2, 3)).await.primary,
        RouteTarget::Group("backup".into())
    );
}

#[tokio::test]
async fn resolve_versioned_captures_pre_read_version() {
    let cfg = RoutingTableConfig {
        rules: vec![rule(&["1.0.0.0/8"], RouteTarget::Direct, None)],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let table = RoutingTable::compile(&cfg).await.unwrap();
    assert_eq!(table.version(), 0);

    let (_d, v_before) = table.resolve_versioned(&v4(1, 2, 3, 4)).await;
    assert_eq!(v_before, 0, "version captured at resolve must be pre-bump");

    // Simulate a watcher reload.
    table.version.fetch_add(1, Ordering::AcqRel);

    // A cache tagged with v_before=0 is now stale (current = 1) and will
    // invalidate on the next lookup — which is exactly the desired
    // behaviour: any decision resolved before the bump re-resolves.
    assert_ne!(table.version(), v_before);

    let (_d, v_after) = table.resolve_versioned(&v4(1, 2, 3, 4)).await;
    assert_eq!(v_after, 1);
}

#[tokio::test]
async fn compile_rejects_inverted_rule_with_empty_cidr_set() {
    let cfg = RoutingTableConfig {
        rules: vec![inverted_rule(&[], RouteTarget::Direct, None)],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    };
    let err = RoutingTable::compile(&cfg).await.unwrap_err().to_string();
    assert!(
        err.contains("invert = true") && err.contains("no prefixes"),
        "unexpected error: {err}"
    );
}
