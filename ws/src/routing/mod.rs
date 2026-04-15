//! Policy routing primitives: CIDR set matcher used by both the legacy
//! bypass module and the upcoming routing table.

pub mod cidr;

pub use cidr::{CidrSet, read_prefixes_from_file};
