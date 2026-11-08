//! Hedged QUIC handshakes: race a fresh source port when the first one goes silent.
//!
//! Some paths discard individual UDP flows (one 5-tuple) outright: every
//! Initial a dial sends from its port — the first and all of quinn's PTO
//! retransmits — vanishes, while a dial started the same millisecond from
//! another port completes in one round trip. Retransmitting on the same port
//! cannot recover from that, so a single dial waits out the whole carrier
//! budget (10 s) and fails. Captured on a datacenter client: 46 of 885
//! handshakes lost every Initial before the server saw any of them.
//!
//! [`race_handshake`] starts the first attempt at once and one more attempt at
//! each point of a schedule while nothing has completed yet. Each attempt is a
//! complete dial on its own endpoint, hence its own source port and 5-tuple.
//! The first attempt to succeed wins; the rest are dropped, which abandons a
//! handshake still in flight and implicitly closes (error code 0) a connection
//! that finished but lost the race, since quinn closes a connection once its
//! last handle is gone.
//!
//! Attempts run inside the caller's task — never `tokio::spawn`ed — because
//! the dial's browser profile and carrier padding are task-local and the
//! attempt reads them when it builds its client config.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use outline_metrics as metrics;
use tokio::time::Instant;
use tracing::{debug, info};

use super::vendored::FirstProbe;
use crate::h3::{TrackedEndpoint, client_endpoint};

/// When further handshake attempts start, measured from the first one.
///
/// Both points match quinn's probe-timeout backoff for a fresh connection
/// (3 × the 333 ms initial RTT, then doubled): by then the first attempt has
/// gone unanswered once and twice. A healthy handshake finishes well before
/// the first point — about two round trips, ~0.7 s even at a 300 ms RTT — so a
/// healthy path never starts a second attempt.
pub(crate) const HEDGE_SCHEDULE: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(3)];

/// How a [`race_handshake`] call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RaceOutcome {
    /// Index of the winning attempt; 0 is the one started first.
    pub(crate) winner: usize,
    /// Attempts started, the winner included.
    pub(crate) started: usize,
}

impl RaceOutcome {
    /// Whether any attempt beyond the first was started.
    pub(crate) fn hedged(&self) -> bool {
        self.started > 1
    }
}

/// Runs `attempt(0)` and, while none has succeeded, `attempt(i)` at
/// `schedule[i - 1]` after the start; returns the first success.
///
/// An attempt's error ends the race only when no other attempt is still in
/// flight: a failed dial (e.g. an ICMP-refused port) is not the silent loss
/// this guards against, and the caller's multi-address failover expects such
/// an error promptly. Otherwise the error is discarded and the race goes on.
/// Attempts that are all silent keep the race pending forever once the
/// schedule is spent: the caller bounds it with its own timeout, whose expiry
/// drops every attempt.
pub(crate) async fn race_handshake<T, F, Fut>(
    mut attempt: F,
    schedule: &[Duration],
) -> Result<(T, RaceOutcome)>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let start = Instant::now();
    let tagged = |index: usize, dial: Fut| async move { (index, dial.await) };
    let mut in_flight = FuturesUnordered::new();
    in_flight.push(tagged(0, attempt(0)));
    let mut started = 1;
    loop {
        let next_start = schedule.get(started - 1).map(|after| start + *after);
        tokio::select! {
            biased;
            Some((index, result)) = in_flight.next() => match result {
                Ok(value) => return Ok((value, RaceOutcome { winner: index, started })),
                Err(error) if in_flight.is_empty() => return Err(error),
                Err(_) => {},
            },
            () = sleep_until_or_never(next_start) => {
                in_flight.push(tagged(started, attempt(started)));
                started += 1;
            },
        }
    }
}

/// Completes a QUIC handshake to `server_addr`, racing fresh source ports on
/// [`HEDGE_SCHEDULE`]; returns the winning connection with its endpoint.
///
/// Every attempt binds its own [`client_endpoint`] (so its own port) and builds
/// its client config inside the attempt, where the task-local dial profile is
/// in scope. `kind` labels the endpoint gauge and the hedge counter; `what`
/// prefixes error messages ("QUIC", "xhttp/h3 QUIC"). `pooled` raises the log
/// of a won hedge to `info`: probes dial far more often and stay at `debug`.
/// Only the QUIC handshake races: the caller layers HTTP/3 on the winner, all
/// within its own carrier budget.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_hedged(
    kind: &'static str,
    what: &'static str,
    server_addr: SocketAddr,
    server_name: &str,
    fwmark: Option<u32>,
    disable_udp_gso: bool,
    first_probe: Option<FirstProbe>,
    pooled: bool,
) -> Result<(TrackedEndpoint, quinn::Connection)> {
    let bind_addr = crate::bind_addr_for(server_addr);
    let started_at = Instant::now();
    let ((endpoint, connection), outcome) = race_handshake(
        |index| {
            if index > 0 {
                debug!(
                    %server_addr,
                    attempt = index,
                    "{what} handshake unanswered, racing a fresh source port"
                );
            }
            // Built here, in the caller's task: the config follows the dial's
            // task-local browser profile.
            let client_config = super::h3_quic_client_config_with_first_probe(first_probe);
            async move {
                let endpoint = client_endpoint(bind_addr, fwmark, disable_udp_gso, kind)
                    .with_context(|| format!("failed to bind {what} endpoint for {server_addr}"))?;
                let connection = endpoint
                    .connect_with(client_config, server_addr, server_name)
                    .with_context(|| {
                        format!("failed to initiate {what} connection to {server_addr}")
                    })?
                    .await
                    .with_context(|| format!("{what} handshake failed for {server_addr}"))?;
                Ok((endpoint, connection))
            }
        },
        &HEDGE_SCHEDULE,
    )
    .await?;
    if outcome.hedged() {
        let extra_won = outcome.winner > 0;
        metrics::record_quic_dial_hedge(kind, extra_won);
        if extra_won {
            let elapsed_ms = started_at.elapsed().as_millis();
            if pooled {
                info!(%server_addr, kind, attempt = outcome.winner, started = outcome.started, elapsed_ms,
                    "{what} handshake won from a fresh source port");
            } else {
                debug!(%server_addr, kind, attempt = outcome.winner, started = outcome.started, elapsed_ms,
                    "{what} handshake won from a fresh source port");
            }
        }
    }
    Ok((endpoint, connection))
}

async fn sleep_until_or_never(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
#[path = "tests/dial_race.rs"]
mod tests;
