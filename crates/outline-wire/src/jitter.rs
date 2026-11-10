//! Interval jitter for periodic on-wire actions (keepalive pings, probes).
//!
//! A timer that fires at an exact period leaves a line in the autocorrelation
//! of packet timestamps that an idle connection otherwise does not have.
//! [`jitter_down`] shortens each period by a random share so consecutive gaps
//! differ. It never lengthens one: every idle timeout and pong deadline that
//! was sized against the configured interval keeps its margin.

use std::time::Duration;

/// Largest share of the interval [`jitter_down`] may cut, in permille.
pub const JITTER_DOWN_MAX_PERMILLE: u32 = 300;

/// Returns `interval` shortened by a uniformly drawn share in
/// `0..=JITTER_DOWN_MAX_PERMILLE` permille, picked by `rand`. The result is in
/// `[0.7 * interval, interval]`. Draw a fresh `rand` for every period.
pub fn jitter_down(interval: Duration, rand: u32) -> Duration {
    let keep_permille = 1000 - rand % (JITTER_DOWN_MAX_PERMILLE + 1);
    interval.mul_f64(f64::from(keep_permille) / 1000.0)
}

#[cfg(test)]
#[path = "tests/jitter.rs"]
mod tests;
