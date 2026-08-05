//! Walking an uplink's wire chain, once, for both ingresses.
//!
//! The loop lives here rather than in each ingress because the two things it
//! must get right are the two things a second copy gets wrong. First, a wire
//! is retired on the outcome of the *whole* attempt — dial plus transport
//! assembly — because an SS handshake that fails after a clean dial means that
//! wire is just as unusable. Second, the parent uplink is only reported as
//! failing once every one of its wires has failed: a single broken carrier
//! must not flap the uplink out of the candidate set, which is what makes
//! within-uplink failover worth having at all.

use anyhow::{Result, anyhow};
use tracing::debug;

use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

/// What one wire attempt concluded.
pub enum WireAttempt<T> {
    /// The wire built a working transport.
    Built(T),
    /// The wire is not applicable on this plane at all — no UDP path
    /// configured, say. Not a failure: it never ran, so it must not move the
    /// wire's state machine. Spelling this as a variant rather than as an
    /// error keeps "this wire is broken" and "this wire was never a candidate"
    /// apart, which the wire weights depend on.
    NotApplicable,
}

impl UplinkManager {
    /// Try each wire of `candidate` in the manager's preferred order, handing
    /// each one to `build`. Returns the first successful build together with
    /// the wire it landed on.
    ///
    /// `build` owns the dial *and* the transport assembly for one wire —
    /// see the module docs for why the split matters. Callers differ in what
    /// they assemble (SS versus VLESS, TUN versus SOCKS binding), which is why
    /// this takes a closure rather than returning a raw stream. The closure is
    /// called at most once per wire and its future is awaited before the next
    /// call, so it may borrow freely from the caller's scope.
    ///
    /// `allow_fallbacks` is the caller's decision, not this loop's: the TUN
    /// ingress passes its `tun_wire_dial` gate, the SOCKS ingress always
    /// passes `true`. See the module docs for why this must not be read from
    /// config in here.
    pub async fn dial_over_wires<T, F, Fut>(
        &self,
        candidate: &UplinkCandidate,
        transport: TransportKind,
        allow_fallbacks: bool,
        mut build: F,
    ) -> Result<(T, u8)>
    where
        F: FnMut(u8) -> Fut,
        Fut: std::future::Future<Output = Result<WireAttempt<T>>>,
    {
        let total_wires = 1 + candidate.uplink.fallbacks.len();
        let order = if allow_fallbacks && total_wires > 1 {
            self.wire_dial_order(candidate.index, transport, total_wires)
        } else {
            // Caller opted out, or there is nothing to fall back to: the
            // primary wire, exactly as before this loop existed. The gate
            // belongs to the caller — see this method's doc — because only the
            // TUN ingress's wire support is new enough to need gating.
            vec![0]
        };

        // Whether this call ever had more than one wire to walk. Gate-off (and
        // any uplink with no fallbacks configured) always resolves `order` to a
        // single entry, so this is known before the loop runs, not derived from
        // how many attempts actually happened.
        let multi_wire = order.len() > 1;

        let mut last_err: Option<anyhow::Error> = None;
        for &wire in &order {
            match build(wire).await {
                Ok(WireAttempt::NotApplicable) => {
                    // Deliberately no `record_wire_outcome`: nothing was
                    // attempted, so there is no outcome. Recording a failure
                    // here would teach the wire weights that a wire is broken
                    // when it was only ever irrelevant on this plane.
                    debug!(
                        uplink = %candidate.uplink.name,
                        wire,
                        "wire is not applicable on this plane, skipping",
                    );
                },
                Ok(WireAttempt::Built(value)) => {
                    // Gate-off must record nothing: `tun_wire_dial` exists so
                    // the binary can be deployed inert and enabled one node at
                    // a time, and a gate-off node only ever tries wire 0. If
                    // it fed that outcome into the shared active-wire state
                    // machine anyway, its primary-wire failures could still
                    // promote `active_wire` to a fallback this ingress never
                    // tried — and the SOCKS ingress on the same
                    // `UplinkManager` reads that same state when it builds its
                    // own dial order. A flag documented as inert must not
                    // change behaviour for a different ingress.
                    if allow_fallbacks {
                        self.record_wire_outcome(
                            candidate.index,
                            transport,
                            wire,
                            true,
                            total_wires,
                        );
                    }
                    if wire != 0 {
                        debug!(
                            uplink = %candidate.uplink.name,
                            wire,
                            "fallback wire dial succeeded",
                        );
                    }
                    return Ok((value, wire));
                },
                Err(error) => {
                    // See the success arm above: gate-off must not record.
                    if allow_fallbacks {
                        self.record_wire_outcome(
                            candidate.index,
                            transport,
                            wire,
                            false,
                            total_wires,
                        );
                    }
                    // Skip the log on a single-wire attempt: "trying the next
                    // one" would be false (there is no next wire) and on
                    // gate-off this line runs for every failed TUN TCP dial,
                    // which is exactly the inert path this flag promises not
                    // to change. The pre-existing per-uplink failure logging
                    // in `select_tcp_candidate_and_connect` already covers
                    // this case.
                    if multi_wire {
                        debug!(
                            uplink = %candidate.uplink.name,
                            wire,
                            error = %format!("{error:#}"),
                            "wire dial failed, trying the next one",
                        );
                    }
                    last_err = Some(error);
                },
            }
        }

        let error = last_err.unwrap_or_else(|| anyhow!("no wires configured"));
        // Only a genuine multi-wire exhaustion earns the "all wires failed"
        // wrapper: it exists to tell a caller that every sibling carrier was
        // tried, which is not true of a single-wire attempt (gate-off, or an
        // uplink with no fallbacks configured). Wrapping unconditionally used
        // to double the uplink name into the error text and, worse, become
        // the metric `detail` label via `normalize_other_runtime_failure_detail`
        // — burying the real cause behind a per-uplink prefix that ate most of
        // the 48-character budget. A single-wire failure must surface its
        // cause exactly as it did before this loop existed.
        if multi_wire {
            Err(error.context(format!("all wires failed on uplink {}", candidate.uplink.name)))
        } else {
            Err(error)
        }
    }
}

/// Test fixture: an SS fallback wire tagged `tag`, distinguishable in URLs
/// but otherwise identical — the tests below never actually dial these, they
/// only need a candidate whose `fallbacks` slice has the right length so
/// `wire_dial_order` sees the right `total_wires`.
#[cfg(test)]
fn fallback_wire(tag: &str) -> crate::config::FallbackTransport {
    use url::Url;

    crate::config::FallbackTransport {
        transport: crate::config::UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("wss://host.example.com/{tag}/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: crate::config::TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("wss://host.example.com/{tag}/udp")).unwrap()),
        udp_xhttp_url: None,
        udp_mode: crate::config::TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: crate::config::TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: crate::config::CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

/// Test fixture: primary + three fallbacks = four wires, the shape
/// `dial_over_wires`'s tests walk. None of these carriers are ever actually
/// dialed — the tests supply a synthetic `build` closure — so the URLs need
/// not be routable.
#[cfg(test)]
fn uplink_with_three_fallbacks() -> crate::config::UplinkConfig {
    use url::Url;

    crate::config::UplinkConfig {
        name: "wire-dial-test".to_string(),
        transport: crate::config::UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://host.example.com/primary/tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: crate::config::TransportMode::WsH1,
        udp_ws_url: Some(Url::parse("wss://host.example.com/primary/udp").unwrap()),
        udp_xhttp_url: None,
        udp_mode: crate::config::TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: crate::config::TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: crate::config::CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![fallback_wire("fb1"), fallback_wire("fb2"), fallback_wire("fb3")],
        shuffle_wires: false,
        carrier_downgrade: false,
        padding: None,
        shuffle_timer: None,
    }
}

#[cfg(test)]
fn test_probe_cfg() -> crate::config::ProbeConfig {
    crate::config::ProbeConfig {
        interval: std::time::Duration::from_secs(10),
        timeout: std::time::Duration::from_secs(10),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 2,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: std::time::Duration::from_secs(300),
        endpoint_check: false,
        endpoint_check_timeout: std::time::Duration::from_millis(2000),
        ws: crate::config::WsProbeConfig { enabled: true },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

#[cfg(test)]
fn test_lb() -> crate::config::LoadBalancingConfig {
    crate::config::LoadBalancingConfig {
        mode: crate::config::LoadBalancingMode::ActiveActive,
        routing_scope: crate::config::RoutingScope::PerFlow,
        shared_resume: false,
        sticky_ttl: std::time::Duration::from_secs(300),
        hysteresis: std::time::Duration::from_millis(50),
        failure_cooldown: std::time::Duration::from_secs(10),
        tcp_chunk0_failover_timeout: std::time::Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.3,
        loss_latency_penalty_k: 0.0,
        loss_latency_inflation_max: 4.0,
        loss_sample_interval: std::time::Duration::from_secs(30),
        loss_sample_min_packets: 50,
        loss_ewma_alpha: 0.2,
        failure_penalty: std::time::Duration::from_millis(500),
        failure_penalty_max: std::time::Duration::from_secs(30),
        failure_penalty_halflife: std::time::Duration::from_secs(60),
        mode_downgrade_duration: std::time::Duration::from_secs(60),
        carrier_degraded_failover: None,
        loss_failover_ratio: 0.0,
        loss_failover_duration: None,
        runtime_failure_window: std::time::Duration::from_secs(60),
        chunk0_failure_window: std::time::Duration::from_secs(300),
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        warm_probe_keepalive_interval: None,
        auto_failback: false,
        health_weighted_selection: false,
        tun_wire_dial: false,
        health_weight_floor: 0.05,
        vless_udp_mux_limits: crate::config::VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: crate::OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: std::time::Duration::from_secs(5),
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        tun_icmp_liveness_window: None,
        bypass_when_down: false,
        reselect_at: Vec::new(),
        reselect_interval: None,
    }
}

/// Test fixture: a manager with one uplink of four wires (primary + three
/// fallbacks), used by `dial_over_wires`'s tests. `allow_fallbacks` is passed
/// directly by those tests (the gate is the caller's job, not this loop's —
/// see the module docs), so the fixture needs no `tun_wire_dial` setting.
#[cfg(test)]
async fn sample_manager_with_three_fallbacks() -> UplinkManager {
    UplinkManager::new_for_test(
        "main",
        vec![uplink_with_three_fallbacks()],
        test_probe_cfg(),
        test_lb(),
    )
    .unwrap()
}

#[cfg(test)]
#[path = "tests/wire_dial.rs"]
mod tests;
