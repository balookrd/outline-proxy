use outline_routing::RouteTarget;

use super::route_target_from_name;

#[test]
fn via_resolves_known_group_reserved_or_errors() {
    // `group_names` is the union of uplink-group names and reverse-group names
    // (the latter added by `load_routing_config` from `[reverse_listener]`), so
    // a `via` onto a reverse group with no `[[uplink_group]]` validates.
    let groups = ["main", "reverse"];
    assert!(matches!(
        route_target_from_name("reverse", &groups, "ctx"),
        Ok(RouteTarget::Group(g)) if &*g == "reverse"
    ));
    assert!(matches!(
        route_target_from_name("direct", &groups, "ctx"),
        Ok(RouteTarget::Direct)
    ));
    assert!(matches!(route_target_from_name("drop", &groups, "ctx"), Ok(RouteTarget::Drop)));
    // Unknown group still rejected.
    assert!(route_target_from_name("nope", &groups, "ctx").is_err());
}
