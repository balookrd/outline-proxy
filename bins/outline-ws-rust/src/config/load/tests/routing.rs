use std::path::Path;

use outline_routing::RouteTarget;
use serde::Deserialize;

use super::{load_routing_config, route_target_from_name};
use crate::config::schema::RouteSection;

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

fn parse_sections(toml_str: &str) -> Vec<RouteSection> {
    #[derive(Deserialize)]
    struct Wrapper {
        route: Vec<RouteSection>,
    }
    toml::from_str::<Wrapper>(toml_str).expect("valid route TOML").route
}

// These exercise `load_routing_config` directly on parsed `[[route]]`
// sections, the same shape the `/control/routes` CRUD endpoint will feed it
// after assembling sections from a `toml_edit` document — no `ConfigFile`
// involved.
#[test]
fn validator_reuse_rejects_two_defaults() {
    let sections = parse_sections(
        "[[route]]\ndefault = true\nvia = \"main\"\n\
         [[route]]\ndefault = true\nvia = \"main\"\n",
    );
    let err = load_routing_config(Some(&sections), &["main"], Path::new("/tmp"))
        .expect_err("two defaults must be rejected");
    assert!(format!("{err:#}").contains("default = true"), "got: {err:#}");
}

#[test]
fn validator_reuse_accepts_valid_list() {
    let sections = parse_sections(
        "[[route]]\nprefixes = [\"10.0.0.0/8\"]\nvia = \"direct\"\n\
         [[route]]\ndefault = true\nvia = \"main\"\n",
    );
    let table = load_routing_config(Some(&sections), &["main"], Path::new("/tmp"))
        .expect("valid list")
        .expect("some table");
    assert_eq!(table.rules.len(), 1);
}
