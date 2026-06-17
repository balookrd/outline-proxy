//! Glue between [`UplinkConfig`] and the transport-crate dial functions.
//!
//! A single helper wraps a future in the per-uplink dial scopes: the
//! fingerprint-profile strategy and the carrier-padding on/off override.
//! Lives in its own module so callers do not have to reach into
//! `crate::config::UplinkConfig` for the field names and
//! `outline_transport::{fingerprint_profile, carrier_padding}` for the
//! scope-builders — all of which are private implementation details that
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
    // Two independent per-uplink overrides, each `None` meaning "inherit the
    // process-wide default": the fingerprint-profile strategy and the
    // carrier-padding on/off. Padding is nested inside the fingerprint scope so
    // a single uplink can pin both without either leaking to siblings on the
    // same host:port.
    match (uplink.fingerprint_profile, uplink.padding) {
        (Some(strategy), Some(on)) => {
            outline_transport::fingerprint_profile::with_strategy_override(
                strategy,
                outline_transport::carrier_padding::with_uplink_padding_override(on, fut),
            )
            .await
        },
        (Some(strategy), None) => {
            outline_transport::fingerprint_profile::with_strategy_override(strategy, fut).await
        },
        (None, Some(on)) => {
            outline_transport::carrier_padding::with_uplink_padding_override(on, fut).await
        },
        (None, None) => fut.await,
    }
}

/// Run `fut` with only the per-uplink carrier-padding override in scope (no
/// fingerprint). The proxy hot path needs this distinct from
/// [`dial_in_uplink_scope`] because the transport is *built* — `split()` plus
/// the writer/reader spawn that read [`outline_transport::carrier_padding`]'s
/// resolved value — **after** the dial future returns. The fingerprint applies
/// during the TLS handshake (inside the dial), but padding is read at build
/// time, so the scope must wrap the dial *and* the build. The fingerprint
/// strategy is left to the global default on the hot path (unchanged); only
/// padding is scoped here.
pub async fn with_uplink_padding_scope<F, T>(uplink: &UplinkConfig, fut: F) -> T
where
    F: Future<Output = T>,
{
    match uplink.padding {
        Some(on) => outline_transport::carrier_padding::with_uplink_padding_override(on, fut).await,
        None => fut.await,
    }
}
