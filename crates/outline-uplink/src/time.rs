//! Tiny duration converters shared across snapshot serialization.

use std::time::Duration;

use tokio::time::Instant;

pub(crate) fn duration_to_millis_option(value: Option<Duration>) -> Option<u128> {
    value.map(|v| v.as_millis())
}

/// How long the loss-elevated episode has been running, for the snapshot.
///
/// `since` is `None` both when no episode is open and when loss-driven
/// failover is switched off entirely, and those must not read the same
/// downstream: the gauge is absent for the second (nothing is watching) but a
/// plain zero for the first (watching, currently quiet). Without the
/// distinction an operator cannot tell a mechanism that has never fired from
/// one that was never armed — the metric stays silent either way.
pub(crate) fn loss_elevated_ms(
    since: Option<Instant>,
    failover_armed: bool,
    now: Instant,
) -> Option<u128> {
    match since {
        Some(since) => Some(now.duration_since(since).as_millis()),
        None => failover_armed.then_some(0),
    }
}
