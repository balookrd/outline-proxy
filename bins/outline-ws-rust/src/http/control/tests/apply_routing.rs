use std::net::Ipv4Addr;
use std::time::Duration;

use outline_routing::config::{RouteRule, RouteTarget, RoutingTableConfig};
use outline_routing::{RoutingTable, SharedRoutingTable};
use socks5_proto::TargetAddr;
use tokio::sync::Mutex;

use super::{rebuild_routing, routing_hot_apply_possible};

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

// `routes_applied` in `handle_apply`'s response comes from matching
// `(&handle.shared_routing, &new_config.routing)`; only the `(Some, Some)` arm
// hot-applies, the other three combinations fall through to `_ => None`. That
// match lives inside `handle_apply`, which needs a full `ApplyHandle` plus a
// `Request<Incoming>` to exercise end to end — `Incoming` has no test
// constructor, so building that fixture just to cover the `None` arms would be
// disproportionate. `routing_hot_apply_possible` pulls the decision out as a
// pure function so all four combinations can be asserted directly instead.
#[tokio::test]
async fn hot_apply_impossible_without_startup_table_or_reloaded_routing() {
    assert!(
        !routing_hot_apply_possible(None, None),
        "no live table and no [[route]] in the reloaded config"
    );
}

#[tokio::test]
async fn hot_apply_impossible_when_reload_drops_routing() {
    let shared =
        SharedRoutingTable::new(RoutingTable::compile(&cfg(RouteTarget::Drop)).await.unwrap());
    assert!(
        !routing_hot_apply_possible(Some(&shared), None),
        "startup table present but reloaded config has no [[route]] anymore"
    );
}

#[tokio::test]
async fn hot_apply_impossible_when_routing_absent_at_startup() {
    let routing_cfg = cfg_direct_10();
    assert!(
        !routing_hot_apply_possible(None, Some(&routing_cfg)),
        "reloaded config declares [[route]] but there is no live table to swap into"
    );
}

#[tokio::test]
async fn hot_apply_possible_when_both_present() {
    let shared =
        SharedRoutingTable::new(RoutingTable::compile(&cfg(RouteTarget::Drop)).await.unwrap());
    let routing_cfg = cfg_direct_10();
    assert!(
        routing_hot_apply_possible(Some(&shared), Some(&routing_cfg)),
        "startup table and reloaded [[route]] both present -> hot-apply possible"
    );
}
