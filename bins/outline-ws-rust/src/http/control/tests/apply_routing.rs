use std::net::Ipv4Addr;
use std::time::Duration;

use outline_routing::config::{RouteRule, RouteTarget, RoutingTableConfig};
use outline_routing::{RoutingTable, SharedRoutingTable};
use socks5_proto::TargetAddr;
use tokio::sync::Mutex;

use super::rebuild_routing;

fn cfg(default: RouteTarget) -> RoutingTableConfig {
    RoutingTableConfig {
        rules: vec![],
        default_target: default,
        default_fallback: None,
    }
}

fn cfg_direct_10() -> RoutingTableConfig {
    RoutingTableConfig {
        rules: vec![RouteRule {
            inline_prefixes: vec!["10.0.0.0/8".to_string()],
            files: vec![],
            inline_domains: vec![],
            domain_files: vec![],
            file_poll: Duration::from_secs(60),
            target: RouteTarget::Direct,
            fallback: None,
            invert: false,
        }],
        default_target: RouteTarget::Group("main".into()),
        default_fallback: None,
    }
}

#[tokio::test]
async fn rebuild_swaps_the_live_table() {
    let shared =
        SharedRoutingTable::new(RoutingTable::compile(&cfg(RouteTarget::Drop)).await.unwrap());
    let watchers = Mutex::new(None);
    // TargetAddr has no FromStr — construct it directly (see tests/table.rs).
    let ip = TargetAddr::IpV4(Ipv4Addr::new(10, 1, 2, 3), 443);
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Drop);

    let count = rebuild_routing(&shared, &cfg_direct_10(), &watchers).await.unwrap();
    assert_eq!(count, 1, "one non-default rule");
    assert_eq!(shared.resolve(&ip).primary, RouteTarget::Direct, "new table is live");
    assert!(shared.version() >= 1, "version advanced");
}
