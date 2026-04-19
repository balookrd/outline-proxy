mod args;
mod load;
mod schema;
mod types;

pub use args::Args;
pub use load::load_config;
pub use types::{AppConfig, H2Config, MetricsConfig};

#[cfg(test)]
pub(crate) use schema::{ConfigFile, resolve_outline_section};

#[cfg(test)]
mod tests;
