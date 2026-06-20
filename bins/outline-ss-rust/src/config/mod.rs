pub mod access_key;
mod cli;
mod dashboard;
mod fallback;
mod file;
mod loader;
mod resolved;
mod sni;
mod tuning;
mod user_entry;
mod validation;

#[cfg_attr(not(feature = "control"), allow(unused_imports))]
pub use dashboard::DashboardInstanceConfig;
pub use dashboard::{ControlConfig, DashboardConfig};
pub use fallback::{BackendProto, HttpFallbackConfig, ProxyProtocolVersion};
pub use loader::AppMode;
#[cfg(test)]
pub use loader::default_http_root_realm;
pub use resolved::{
    AccessKeyConfig, Config, H3Alpn, PaddingConfig, ReverseProtocol, ReverseTunnelEndpoint,
    SessionResumptionConfig,
};
pub use sni::{SniBackend, SniFallbackConfig, SniMatcher, TlsCertEntry};
pub use tuning::{TuningOverrides, TuningPreset, TuningProfile};
pub use user_entry::{CipherKind, ConfigError, UserEntry, validate_ip_aliases};
// Surfaced for the control plane and tests; under `--no-default-features`
// (control off) nothing in the binary consumes this re-export.
#[cfg_attr(not(feature = "control"), allow(unused_imports))]
pub use user_entry::OneOrManyCidr;
