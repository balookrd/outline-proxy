//! Glue between [`UplinkConfig`] and the transport-crate dial functions.
//!
//! Right now this is a single helper that wraps a future in a
//! per-uplink fingerprint-profile scope. Lives in its own module so
//! callers do not have to reach into `crate::config::UplinkConfig` for
//! the field name and `outline_transport::fingerprint_profile` for the
//! scope-builder — both pieces are private implementation details that
//! the dial path otherwise should not care about.

use std::future::Future;

use crate::config::UplinkConfig;

/// Run `fut` with the per-uplink fingerprint-profile override (if any)
/// in effect. When the uplink does not pin a strategy, the future
/// runs unchanged and inherits the process-wide value set by
/// [`outline_transport::init_fingerprint_profile_strategy`]. When it
/// does, the transport-layer `select` reads the override instead, so
/// only this uplink's dials get the matching profile while siblings
/// on the same `host:port` keep theirs.
///
/// The scope only applies to code that runs inside the awaited future
/// directly — `tokio::spawn` children inside the dial driver do not
/// inherit it, which is intentional: every `select` call lives at the
/// dial entry-point, not in a freshly-spawned post-handshake task.
pub async fn dial_in_uplink_scope<F, T>(uplink: &UplinkConfig, fut: F) -> T
where
    F: Future<Output = T>,
{
    match uplink.fingerprint_profile {
        Some(strategy) => {
            outline_transport::fingerprint_profile::with_strategy_override(strategy, fut).await
        },
        None => fut.await,
    }
}
