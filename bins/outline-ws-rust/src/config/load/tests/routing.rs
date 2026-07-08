use outline_routing::RouteTarget;

use super::route_target_from_name;

#[test]
fn via_resolves_known_group_reserved_or_errors() {
    // A `via` onto a configured uplink-group name resolves to that group.
    let groups = ["main", "backup"];
    assert!(matches!(
        route_target_from_name("backup", &groups, "ctx"),
        Ok(RouteTarget::Group(g)) if &*g == "backup"
    ));
    assert!(matches!(
        route_target_from_name("direct", &groups, "ctx"),
        Ok(RouteTarget::Direct)
    ));
    assert!(matches!(route_target_from_name("drop", &groups, "ctx"), Ok(RouteTarget::Drop)));
    // Unknown group still rejected.
    assert!(route_target_from_name("nope", &groups, "ctx").is_err());
}
