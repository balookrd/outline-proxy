mod args;
mod compat;
mod load;
mod migrate;
mod schema;
mod types;

pub use args::Args;
pub use load::load_config;
pub use migrate::migrate_config_file;
pub use types::{
    AppConfig, ControlConfig, DashboardConfig, DashboardInstanceConfig, H2Config, MetricsConfig,
};

#[cfg(test)]
pub(crate) use compat::normalize_outline_section;
#[cfg(test)]
pub(crate) use schema::ConfigFile;

#[cfg(feature = "control")]
pub(crate) use load::validate_uplink_section;
#[cfg(feature = "control")]
pub(crate) use schema::UplinkSection;

#[cfg(test)]
mod tests;
