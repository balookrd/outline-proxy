//! DNS data-path probe.  Sends a single A query through the uplink's UDP
//! tunnel and verifies the response transaction id and rcode — enough to
//! detect that the far side is reachable, addressed correctly, and returning
//! well-formed DNS packets.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout, timeout_at};
use tracing::debug;

use outline_transport::{DnsCache, TransportOperation, UdpWsTransport, VlessUdpWsTransport};

use crate::config::{
    DnsProbeConfig, SsPathKind, TargetAddr, TransportMode, UplinkConfig, UplinkTransport,
};
use crate::manager::probe::warm_udp::{self, WarmUdpProbe, WarmUdpProbeSlot};

use super::metrics::BytesRecorder;

/// How much earlier than the caller's `budget` the fresh dial gives up, so it
/// reports where it stalled before the caller's own timeout cuts it off.
const FRESH_DIAL_SLACK: Duration = Duration::from_millis(100);

/// The step a DNS probe attempt has reached, kept outside the attempt's future
/// so a timeout that drops the future can still say where it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Phase {
    /// Waiting for a probe dial permit.
    Queue = 0,
    /// Dialling the carrier and opening the tunnel session.
    Dial = 1,
    /// Sending the query.
    Send = 2,
    /// Waiting for the answer.
    Read = 3,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Queue => "queue",
            Self::Dial => "dial",
            Self::Send => "send",
            Self::Read => "read",
        })
    }
}

#[derive(Debug)]
pub(crate) struct PhaseMark(AtomicU8);

impl PhaseMark {
    pub(crate) fn new() -> Self {
        Self(AtomicU8::new(Phase::Queue as u8))
    }

    pub(crate) fn set(&self, phase: Phase) {
        self.0.store(phase as u8, Ordering::Relaxed);
    }

    pub(crate) fn get(&self) -> Phase {
        match self.0.load(Ordering::Relaxed) {
            0 => Phase::Queue,
            1 => Phase::Dial,
            2 => Phase::Send,
            _ => Phase::Read,
        }
    }
}

pub(crate) fn stalled(budget: Duration, phase: Phase) -> anyhow::Error {
    anyhow!("no answer within {} ms at {phase}", budget.as_millis())
}

/// Run the DNS probe, first through the warm transport cached by an earlier
/// cycle (if any), and once more through a fresh dial if that fails.
///
/// A warm transport can be dead without the client knowing: the server reaps
/// a VLESS session that has carried nothing for its pong deadline, and on an
/// active uplink the probe runs only every `liveness_interval` while the slot
/// keepalive stays off. Reporting that as a failed probe would cap the UDP
/// carrier (H3 → H2) for a path that works, so only the fresh dial's outcome
/// counts. The warm attempt gets half of `budget`, leaving the rest to the
/// redial: datagrams into a reaped session are dropped silently, so the warm
/// read may never return on its own.
///
/// The redial stops [`FRESH_DIAL_SLACK`] short of `budget`, so a stall comes
/// back as an error naming the step it stalled at, with the warm attempt's
/// failure attached, rather than as the caller's bare timeout.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_dns_probe(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &DnsProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_udp_mode: TransportMode,
    warm_slot: Option<&WarmUdpProbeSlot>,
    budget: Duration,
) -> Result<(bool, Option<TransportMode>)> {
    let started = Instant::now();
    let deadline = started + budget.saturating_sub(FRESH_DIAL_SLACK);
    let warm_ready = warm_slot.is_some_and(|slot| warm_udp::peek_matches(slot, effective_udp_mode));
    let mut warm_error = None;
    if warm_ready {
        let warm_budget = budget / 2;
        let mut used_warm = false;
        let phase = PhaseMark::new();
        let attempt = run_dns_probe_once(
            cache,
            group,
            uplink,
            probe,
            Arc::clone(&dial_limit),
            effective_udp_mode,
            warm_slot,
            true,
            &mut used_warm,
            &phase,
        );
        let error = match timeout(warm_budget, attempt).await {
            Ok(Ok(outcome)) => return Ok(outcome),
            // The slot emptied between the peek and the take, so this was
            // already a fresh dial: its failure is the probe's answer.
            Ok(Err(error)) if !used_warm => return Err(error),
            Ok(Err(error)) => format!("{error:#}"),
            Err(_) => format!("{:#}", stalled(warm_budget, phase.get())),
        };
        debug!(
            uplink = %uplink.name,
            transport = "udp",
            probe = "dns",
            error,
            "warm DNS probe transport failed, retrying with a fresh dial"
        );
        warm_error = Some(error);
    }
    let mut used_warm = false;
    let phase = PhaseMark::new();
    let fresh_started = Instant::now();
    let attempt = run_dns_probe_once(
        cache,
        group,
        uplink,
        probe,
        dial_limit,
        effective_udp_mode,
        warm_slot,
        false,
        &mut used_warm,
        &phase,
    );
    let result = match timeout_at(deadline, attempt).await {
        Ok(result) => result,
        Err(_) => Err(stalled(fresh_started.elapsed(), phase.get())),
    };
    match warm_error {
        Some(warm) => {
            result.with_context(|| format!("fresh dial after the warm transport failed ({warm})"))
        },
        None => result,
    }
}

/// One DNS probe round-trip. With `allow_warm` it takes the warm transport
/// from `warm_slot` when the slot holds one at `effective_udp_mode` and sets
/// `used_warm`; otherwise it dials fresh. Either way a successful transport is
/// stashed back into the slot.
#[allow(clippy::too_many_arguments)]
async fn run_dns_probe_once(
    cache: &DnsCache,
    group: &str,
    uplink: &UplinkConfig,
    probe: &DnsProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_udp_mode: TransportMode,
    warm_slot: Option<&WarmUdpProbeSlot>,
    allow_warm: bool,
    used_warm: &mut bool,
    phase: &PhaseMark,
) -> Result<(bool, Option<TransportMode>)> {
    let dns_server = probe.target_addr()?;
    let query = build_dns_query(&probe.name);

    let bytes = BytesRecorder {
        group,
        uplink: &uplink.name,
        transport: "udp",
        probe: "dns",
    };

    match uplink.transport {
        UplinkTransport::Ss => {
            let mut payload = dns_server.to_wire_bytes()?;
            payload.extend_from_slice(&query);

            // WS uplinks are eligible for warm reuse: the SS-UDP wire
            // form already carries the target on every datagram, so a
            // cached transport just means "keep the WS open" — no
            // per-session state to worry about.
            let warm_taken = warm_slot
                .filter(|_| allow_warm)
                .and_then(|slot| warm_udp::take_if_matches(slot, effective_udp_mode));

            let (transport, downgraded_from, dialed_fresh) = match warm_taken {
                Some(WarmUdpProbe::Ws { transport, .. }) => (transport, None, false),
                Some(WarmUdpProbe::Vless { transport, .. }) => {
                    // Wrong variant for this WS branch — should not
                    // happen (slot is keyed per uplink) but guard rather
                    // than panic.
                    *used_warm = true;
                    let _ = transport.close().await;
                    return Err(anyhow!(
                        "warm UDP slot for WS uplink {} held a non-WS transport",
                        uplink.name
                    ));
                },
                None => {
                    let (t, downgraded) = {
                        let _permit =
                            dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
                        phase.set(Phase::Dial);
                        // `udp_dial_url()` is combined-SS-aware: it returns
                        // `ss_xhttp_url`/`ss_ws_url` for a combined wire and the
                        // split `udp_ws_url`/`udp_xhttp_url` otherwise. Reading
                        // `udp_ws_url` directly here used to fail combined uplinks
                        // with "has no udp_ws_url for DNS probe".
                        let udp_ws_url = uplink.udp_dial_url().ok_or_else(|| {
                            anyhow!("uplink {} has no udp dial URL for DNS probe", uplink.name)
                        })?;
                        // Use `connect_with_resume(..., None)` so the WS-mode
                        // downgrade marker propagates. DNS probes do not
                        // participate in cross-transport session resumption, so
                        // the SessionId tuple element is discarded.
                        //
                        // Scope the per-uplink padding override over the dial +
                        // build so a probe to a padded per-uplink SS-UDP path
                        // frames its datagrams (the transport reads
                        // `effective_carrier_padding` at build). The global
                        // default is unaffected by an absent override — mirrors
                        // the VLESS-UDP probe.
                        let connect = UdpWsTransport::connect_with_resume(
                            cache,
                            udp_ws_url,
                            effective_udp_mode,
                            uplink.cipher,
                            &uplink.password,
                            uplink.dial_network(),
                            "probe_dns",
                            None,
                            None,
                            uplink.combined_ss_kind(SsPathKind::Udp),
                        );
                        let (t, _issued, downgraded) =
                            crate::dial::with_uplink_padding_scope(uplink, connect)
                                .await
                                .with_context(|| TransportOperation::Connect {
                                    target: format!(
                                        "DNS probe websocket for uplink {}",
                                        uplink.name
                                    ),
                                })?;
                        (t, downgraded)
                    };
                    (t, downgraded, true)
                },
            };
            *used_warm = !dialed_fresh;

            let result = async {
                phase.set(Phase::Send);
                transport
                    .send_packet(&payload)
                    .await
                    .context("failed to send DNS probe packet")?;
                bytes.outgoing(payload.len());
                phase.set(Phase::Read);
                let response = transport
                    .read_packet()
                    .await
                    .context("failed to read DNS probe response")?;
                bytes.incoming(response.len());
                let (_, consumed) = TargetAddr::from_wire_bytes(&response)?;
                validate_dns_response(&response[consumed..], &query)?;
                Ok::<bool, anyhow::Error>(true)
            }
            .await;

            // Stash the WS transport for the next cycle on success +
            // no-downgrade. Any error path falls through to the close branch.
            let keep_warm = result.is_ok() && downgraded_from.is_none() && warm_slot.is_some();
            if keep_warm {
                if let Some(slot) = warm_slot {
                    warm_udp::put_back(
                        slot,
                        WarmUdpProbe::Ws { transport, mode: effective_udp_mode },
                    );
                }
            } else {
                debug!(
                    uplink = %uplink.name,
                    transport = "udp",
                    probe = "dns",
                    dialed_fresh,
                    "closing probe transport after DNS probe"
                );
                if let Err(error) = transport.close().await {
                    debug!(
                        uplink = %uplink.name,
                        transport = "udp",
                        probe = "dns",
                        error = %format!("{error:#}"),
                        "probe transport close returned error during teardown"
                    );
                }
            }
            result.map(|ok| (ok, downgraded_from))
        },
        UplinkTransport::Vless => {
            let udp_ws_url = uplink.udp_dial_url().ok_or_else(|| {
                anyhow!("uplink {} has no vless dial URL for DNS probe", uplink.name)
            })?;
            let uuid = uplink
                .vless_id
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} has no vless_id for DNS probe", uplink.name))?;

            // Try to reuse a transport cached from a previous probe cycle.
            // Same uplink + same effective mode + same probe target ⇒ the
            // server-side NAT entry, reader task, and DNS resolve for the
            // probe target stay hot. A fresh dial pays all three on every
            // probe, which dominates UDP-probe latency vs. TCP.
            let warm_taken = warm_slot
                .filter(|_| allow_warm)
                .and_then(|slot| warm_udp::take_if_matches(slot, effective_udp_mode));

            let (transport, downgraded_from, dialed_fresh) = match warm_taken {
                Some(WarmUdpProbe::Vless { transport, .. }) => (transport, None, false),
                Some(WarmUdpProbe::Ws { transport, .. }) => {
                    // Wrong variant for this VLESS branch — should not
                    // happen (slot is keyed per uplink) but guard rather
                    // than panic.
                    *used_warm = true;
                    let _ = transport.close().await;
                    return Err(anyhow!(
                        "warm UDP slot for VLESS uplink {} held a non-VLESS transport",
                        uplink.name
                    ));
                },
                None => {
                    // Use `connect_with_resume(..., None)` so the WS-mode downgrade
                    // marker propagates the same way as the SS branch above. DNS
                    // probes do not participate in cross-transport session
                    // resumption — the SessionId tuple element is discarded.
                    let (t, downgraded) = {
                        let _permit =
                            dial_limit.acquire_owned().await.expect("probe dial semaphore closed");
                        phase.set(Phase::Dial);
                        // Scope the per-uplink padding override over the
                        // dial + build so a probe to a padded per-uplink VLESS
                        // path frames its datagrams (the transport reads
                        // `effective_carrier_padding` at build). The global
                        // default is unaffected by an absent override.
                        let connect = VlessUdpWsTransport::connect_with_resume(
                            cache,
                            udp_ws_url,
                            effective_udp_mode,
                            uuid,
                            &dns_server,
                            uplink.dial_network(),
                            "probe_dns",
                            None,
                            None,
                        );
                        // The probe's own carrier is deliberately not registered:
                        // it is a short-lived socket that never carries user
                        // traffic, so its counters would describe the probe rather
                        // than the data path.
                        let (t, _issued, downgraded, _probe) =
                            crate::dial::with_uplink_padding_scope(uplink, connect)
                                .await
                                .with_context(|| TransportOperation::Connect {
                                    target: format!(
                                        "DNS probe VLESS websocket for uplink {}",
                                        uplink.name
                                    ),
                                })?;
                        (t, downgraded)
                    };
                    (t, downgraded, true)
                },
            };
            *used_warm = !dialed_fresh;

            let result = async {
                phase.set(Phase::Send);
                transport
                    .send_packet(&query)
                    .await
                    .context("failed to send DNS probe packet")?;
                bytes.outgoing(query.len());
                phase.set(Phase::Read);
                let response = transport
                    .read_packet()
                    .await
                    .context("failed to read DNS probe response")?;
                bytes.incoming(response.len());
                validate_dns_response(&response, &query)?;
                Ok::<bool, anyhow::Error>(true)
            }
            .await;

            // On success: stash the transport for the next cycle. On error:
            // drop it (the underlying stream may be half-broken). A fresh-
            // dial result that produced a downgrade marker is also dropped
            // — `effective_udp_mode` for the next cycle will reflect the
            // new clamp, so a cached transport at the old mode would just
            // be discarded by `take_if_matches` anyway; closing it now
            // releases the server-side NAT entry promptly.
            let keep_warm = result.is_ok() && downgraded_from.is_none() && warm_slot.is_some();
            if keep_warm {
                if let Some(slot) = warm_slot {
                    warm_udp::put_back(
                        slot,
                        WarmUdpProbe::Vless { transport, mode: effective_udp_mode },
                    );
                }
            } else {
                debug!(
                    uplink = %uplink.name,
                    transport = "udp",
                    probe = "dns",
                    dialed_fresh,
                    "closing probe transport after DNS probe"
                );
                if let Err(error) = transport.close().await {
                    debug!(
                        uplink = %uplink.name,
                        transport = "udp",
                        probe = "dns",
                        error = %format!("{error:#}"),
                        "probe transport close returned error during teardown"
                    );
                }
            }
            result.map(|ok| (ok, downgraded_from))
        },
    }
}

pub(crate) fn validate_dns_response(dns: &[u8], query: &[u8]) -> Result<()> {
    if dns.len() < 12 {
        bail!("DNS probe response is too short");
    }
    if dns[..2] != query[..2] {
        bail!("DNS probe transaction id mismatch");
    }
    if dns[3] & 0x0f != 0 {
        bail!("DNS probe returned non-zero rcode");
    }
    Ok(())
}

pub(crate) fn build_dns_query(name: &str) -> Vec<u8> {
    let txid = 0x5353u16.to_be_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&txid);
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    out
}

#[cfg(test)]
#[path = "tests/dns.rs"]
mod tests;
