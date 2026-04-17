//! Policy routing primitives: CIDR set matcher and runtime routing table.

pub mod cidr;
pub mod table;

pub use cidr::{CidrSet, read_prefixes_from_file};
pub use table::{CompiledRule, RouteDecision, RoutingTable, spawn_route_watchers};
