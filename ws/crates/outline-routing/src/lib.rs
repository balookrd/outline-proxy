//! Policy routing primitives: CIDR set matcher, declarative rule config,
//! and the runtime routing table.
//!
//! Extracted from the main binary so the matcher and the rule model can be
//! unit-tested and reused independently.

pub mod cidr;
pub mod config;
pub mod table;

pub use cidr::{CidrSet, read_prefixes_from_file};
pub use config::{RouteRule, RouteTarget, RoutingTableConfig};
pub use table::{CompiledRule, RouteDecision, RoutingTable, spawn_route_watchers};
