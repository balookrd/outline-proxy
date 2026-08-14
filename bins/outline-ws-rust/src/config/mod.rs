mod args;
mod compat;
mod load;
mod schema;
mod types;

pub use args::Args;
pub use load::load_config;
pub use types::{AppConfig, ControlConfig, H2Config, MetricsConfig};

#[cfg(test)]
pub(crate) use compat::normalize_outline_section;
#[cfg(test)]
pub(crate) use load::load_balancing_config;
#[cfg(test)]
pub(crate) use schema::ConfigFile;

#[cfg(feature = "control")]
pub(crate) use load::validate_uplink_section;
#[cfg(feature = "control")]
pub(crate) use schema::UplinkSection;

// Surfaced ahead of their consumer: the `/control/routes` CRUD endpoint (not
// yet added to this binary) will reuse this validator on `[[route]]` sections
// it assembles itself from a `toml_edit` document, instead of building a
// whole `ConfigFile`.
#[cfg(feature = "control")]
pub(crate) use load::load_routing_config;
#[cfg(feature = "control")]
pub(crate) use schema::RouteSection;

// The `groups_crud` control endpoint reuses this validator on
// `[[uplink_group]]` sections it assembles itself from a `toml_edit`
// document, instead of building a whole `ConfigFile` — same pattern as
// `load_routing_config` above. `UplinkGroupSection` is consumed by
// `http::control::groups_crud::payload::table_to_section`;
// `load_balancing_config_from_group` is consumed by
// `http::control::groups_crud::mutate::validate_group_policy`.
#[cfg(feature = "control")]
pub(crate) use load::load_balancing_config_from_group;
#[cfg(feature = "control")]
pub(crate) use schema::UplinkGroupSection;

#[cfg(test)]
mod tests;
