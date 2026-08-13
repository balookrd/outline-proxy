use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

use socks5_proto::TargetAddr;

use crate::config::{RouteRule, RouteTarget, RoutingTableConfig};
use crate::shared::SharedRoutingTable;
use crate::table::RoutingTable;

fn direct_only_config() -> RoutingTableConfig {
    RoutingTableConfig {
        rules: vec![RouteRule {
            inline_prefixes: vec!["10.0.0.0/8".to_string()],
            files: vec![],
            inline_domains: vec![],
            domain_files: vec![],
            file_poll: std::time::Duration::from_secs(60),
            target: RouteTarget::Direct,
            fallback: None,
            invert: false,
        }],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    }
}

fn drop_default_config() -> RoutingTableConfig {
    RoutingTableConfig {
        rules: vec![],
        default_target: RouteTarget::Drop,
        default_fallback: None,
    }
}

#[tokio::test]
async fn swap_preserves_version_monotonicity() {
    let first = RoutingTable::compile(&direct_only_config()).await.unwrap();
    // Simulate a table that has already been reloaded a few times.
    first.version.store(5, Ordering::Release);
    let shared = SharedRoutingTable::new(first);
    assert_eq!(shared.version(), 5);

    let second = RoutingTable::compile(&drop_default_config()).await.unwrap();
    assert_eq!(second.version.load(Ordering::Acquire), 0, "fresh compile starts at 0");

    shared.swap_preserving_version(second);
    assert_eq!(shared.version(), 6, "version must continue from the old table, not reset to 0");
}

#[tokio::test]
async fn resolve_reflects_the_swapped_table() {
    let shared =
        SharedRoutingTable::new(RoutingTable::compile(&direct_only_config()).await.unwrap());
    // `TargetAddr` has no `FromStr` (it only decodes the SOCKS5 ATYP wire
    // shape); build it directly, matching `tests/table.rs`'s convention.
    let ip = TargetAddr::IpV4(Ipv4Addr::new(10, 1, 2, 3), 443);
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Direct);

    shared.swap_preserving_version(RoutingTable::compile(&drop_default_config()).await.unwrap());
    // 10.0.0.0/8 rule is gone; everything now hits the drop default.
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Drop);
}
