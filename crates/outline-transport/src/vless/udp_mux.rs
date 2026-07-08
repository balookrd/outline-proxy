//! Lazy per-target VLESS-UDP session multiplexer that exposes a
//! Shadowsocks-shaped (SOCKS5-framed) datagram API.
//!
//! Shadowsocks UDP multiplexes all destinations through one encrypted session
//! (the target address is carried as a SOCKS-style atyp prefix in every
//! datagram). VLESS UDP has no such prefix: the target is locked into the
//! request header at session open, so each destination needs its own
//! WebSocket session. `VlessUdpSessionMux` provides an SS-shaped API
//! (`send_packet(socks5_framed_payload)` / `read_packet() -> socks5_framed`)
//! on top of a lazy map of per-target VLESS sessions.
//!
//! The session map, janitor and downlink fan-in live in the carrier-generic
//! [`super::udp_mux_core::VlessUdpMuxCore`] (shared with the raw-QUIC mux);
//! this module contributes the WS dial path and its side-channel
//! bookkeeping: per-target resume IDs and the H3-downgrade latch.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use parking_lot::RwLock as SyncRwLock;
use socks5_proto::TargetAddr;
use url::Url;

use crate::{
    DnsCache, TransportOperation, UplinkConnectionBinding, config::TransportMode,
    resumption::SessionId,
};

use super::udp::VlessUdpWsTransport;
#[cfg(all(test, feature = "metrics"))]
use super::udp_mux_core::VlessUdpMuxSessionEntry;
use super::udp_mux_core::{
    VlessUdpMuxCore, VlessUdpMuxDial, VlessUdpMuxLimits, VlessUdpMuxSession,
};

impl VlessUdpMuxSession for VlessUdpWsTransport {
    async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        VlessUdpWsTransport::send_packet(self, payload).await
    }

    async fn read_packet(&self) -> Result<Bytes> {
        VlessUdpWsTransport::read_packet(self).await
    }

    async fn close(&self) -> Result<()> {
        VlessUdpWsTransport::close(self).await
    }
}

/// Synchronous callback fired by the mux the first time a per-target dial
/// silently downgrades from H3 to H2/H1 (host-level `ws_mode_cache` clamp
/// or inline H3-handshake fallback inside `connect_transport`).
/// Receives the originally-requested mode so the uplink-manager caller can
/// record it via `note_silent_transport_fallback`. The dial succeeded but at
/// a lower mode, so passing the requested mode directly is cleaner than
/// synthesising an error to extract the mode from.
pub type VlessUdpDowngradeNotifier = Arc<dyn Fn(TransportMode) + Send + Sync>;

pub struct VlessUdpSessionMux {
    core: VlessUdpMuxCore<WsVlessUdpDialer>,
}

/// Captured connection parameters used to dial a new per-target VLESS UDP
/// session on demand, plus the WS-specific per-dial side channels.
struct WsVlessUdpDialer {
    dns_cache: Arc<DnsCache>,
    url: Url,
    mode: TransportMode,
    uuid: [u8; 16],
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    keepalive_interval: Option<Duration>,
    /// Session IDs the server assigned to each per-target VLESS-UDP-WS
    /// session, keyed by target. On the *next* dial for the same
    /// target the cached ID is presented as `X-Outline-Resume`, so a
    /// feature-enabled outline-ss-rust server can re-attach the
    /// parked `Arc<UdpSocket>` instead of binding a fresh source
    /// port. The map is intentionally separate from the global
    /// `outline_transport::ResumeCache` because a single uplink mux
    /// fans out to many targets and each carries its own Session ID.
    resume_ids: SyncRwLock<HashMap<TargetAddr, SessionId>>,
    /// Optional hook fired the first time a per-target dial returns a
    /// stream that was silently downgraded from H3 to H2/H1 by the
    /// transport layer. Latched: subsequent downgraded dials are
    /// suppressed by `downgrade_reported` so we don't spam the
    /// uplink-manager once per target. Set via
    /// [`VlessUdpSessionMux::with_on_downgrade`].
    on_downgrade: Option<VlessUdpDowngradeNotifier>,
    /// Latch for `on_downgrade`: ensures the notifier fires at most once
    /// per mux instance regardless of how many per-target sessions are
    /// dialed during the H3 outage.
    downgrade_reported: AtomicBool,
    /// Per-uplink carrier-padding override applied around every per-target
    /// dial. The mux dials lazily (on the first packet to a target), outside
    /// the manager's acquire scope, so a dial-scoped task-local would not
    /// survive — the override is captured here and re-applied per dial.
    /// `None` inherits the global `[padding]` default.
    padding_override: Option<bool>,
    /// Carrier control-signal handler installed on every per-target VLESS-UDP
    /// transport this mux dials, so a server downstream-throttle notice on any
    /// target's carrier penalises the uplink. `None` keeps the transports
    /// inert. Set via [`VlessUdpSessionMux::with_throttle_handle`].
    throttle: Option<crate::ThrottleSignalHandle>,
}

impl VlessUdpMuxDial for WsVlessUdpDialer {
    type Session = VlessUdpWsTransport;

    async fn dial(&self, target: &TargetAddr) -> Result<Arc<VlessUdpWsTransport>> {
        // Cross-transport resumption: present the previously-issued
        // Session ID for this target so a feature-enabled server can
        // re-attach its parked `Arc<UdpSocket>` instead of binding a
        // fresh source port.
        let resume_request = self.resume_ids.read().get(target).copied();
        let connect = VlessUdpWsTransport::connect_with_resume(
            &self.dns_cache,
            &self.url,
            self.mode,
            &self.uuid,
            target,
            self.fwmark,
            self.ipv6_first,
            self.source,
            self.keepalive_interval,
            resume_request,
        );
        // Apply the per-uplink padding override around the dial + transport
        // build (VLESS-UDP pads per-datagram, and `connect_with_resume` builds
        // the transport, which reads `effective_carrier_padding`). `None`
        // inherits the global default.
        let dial_result = match self.padding_override {
            Some(on) => crate::carrier_padding::with_uplink_padding_override(on, connect).await,
            None => connect.await,
        };
        let (raw_transport, issued, downgraded_from) =
            dial_result.with_context(|| TransportOperation::Connect {
                target: format!("vless udp session to {target}"),
            })?;
        if let Some(id) = issued {
            self.resume_ids.write().insert(target.clone(), id);
        }
        // Mirror a transport-level WS-mode downgrade (clamp or inline
        // H3→H2/H1 fallback) into the uplink-manager via the latched
        // hook. The compare_exchange ensures the notifier fires at
        // most once per mux instance even if multiple per-target
        // dials race during the same H3 outage window.
        //
        // Reset the latch on the first dial that succeeds at the
        // requested mode after a previous downgrade — this lets the
        // hook fire again if H3 recovers and then drops out a second
        // time during the lifetime of this mux instance.  Without
        // this the latch would be one-shot for the lifetime of the
        // process under long-lived muxes, hiding subsequent outages
        // from the per-uplink window.
        match downgraded_from {
            Some(requested) => {
                if let Some(hook) = self.on_downgrade.as_ref()
                    && self
                        .downgrade_reported
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    hook(requested);
                }
            },
            None => {
                // Cheap relaxed-style store; racing with a Some-branch
                // CAS just means the next downgraded dial flips it
                // back to true via the same CAS.
                self.downgrade_reported.store(false, Ordering::Release);
            },
        }
        // Install the carrier control-signal handler before sharing the
        // transport (no-op unless padding is on and a handle was set).
        let raw_transport = match &self.throttle {
            Some(handle) => raw_transport.with_throttle_handle(handle.clone()),
            None => raw_transport,
        };
        Ok(Arc::new(raw_transport))
    }
}

impl VlessUdpSessionMux {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dns_cache: Arc<DnsCache>,
        url: Url,
        mode: TransportMode,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Self {
        Self::new_with_limits(
            dns_cache,
            url,
            mode,
            uuid,
            fwmark,
            ipv6_first,
            source,
            keepalive_interval,
            VlessUdpMuxLimits::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_limits(
        dns_cache: Arc<DnsCache>,
        url: Url,
        mode: TransportMode,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        limits: VlessUdpMuxLimits,
    ) -> Self {
        let dialer = WsVlessUdpDialer {
            dns_cache,
            url,
            mode,
            uuid,
            fwmark,
            ipv6_first,
            source,
            keepalive_interval,
            resume_ids: SyncRwLock::new(HashMap::new()),
            on_downgrade: None,
            downgrade_reported: AtomicBool::new(false),
            padding_override: None,
            throttle: None,
        };
        Self {
            core: VlessUdpMuxCore::new(dialer, limits, "vless udp", source),
        }
    }

    /// Attach a downgrade-detection hook fired the first time a per-target
    /// dial returns a stream that was silently downgraded from H3 to H2/H1
    /// by the transport layer (host-level `ws_mode_cache` clamp or inline
    /// fallback inside `connect_transport`). Latched: fires at
    /// most once per mux instance regardless of how many subsequent dials
    /// also see the downgrade. Without this, `effective_udp_mode` keeps
    /// reporting H3 in the uplink-manager while every actual session dial
    /// is silently clamped to H2 — the "vless/ws/h3 stays put" symptom.
    pub fn with_on_downgrade(mut self, hook: Option<VlessUdpDowngradeNotifier>) -> Self {
        self.core.dial.on_downgrade = hook;
        self
    }

    /// Set the per-uplink carrier-padding override applied around every
    /// per-target dial. `None` (default) inherits the global `[padding]`
    /// default; `Some(true)`/`Some(false)` force padding on/off for this
    /// uplink's VLESS-UDP sessions. The uplink manager sets this from the
    /// uplink's `padding` config so a lazy per-target dial — which runs
    /// outside the dial-scoped override — still pads correctly.
    pub fn with_padding_override(mut self, padding: Option<bool>) -> Self {
        self.core.dial.padding_override = padding;
        self
    }

    /// Install a carrier control-signal handler on every per-target VLESS-UDP
    /// transport this mux dials, so a server downstream-throttle notice nudges
    /// the uplink switch. No-op at runtime unless padding is on.
    pub fn with_throttle_handle(mut self, handle: Option<crate::ThrottleSignalHandle>) -> Self {
        self.core.dial.throttle = handle;
        self
    }

    /// Attribute the mux's lifetime guard to a concrete uplink so it
    /// participates in `outline_ws_rust_uplink_open_connections` and the
    /// matching close-classification counter alongside per-session lifetimes.
    /// Same constraints as [`crate::UdpWsTransport::with_uplink_binding`].
    pub fn with_uplink_binding(mut self, binding: UplinkConnectionBinding) -> Self {
        self.core.attach_uplink_binding(binding);
        self
    }

    /// Send a SOCKS5-framed UDP payload (`atyp || addr || port || data`).
    /// The target is parsed out to select an existing VLESS session or open
    /// a new one; only the `data` portion crosses the VLESS wire, since the
    /// target is already bound into the session's request header.
    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        self.core.send_packet(socks5_payload).await
    }

    /// Read the next downlink datagram as a SOCKS5-framed payload, with the
    /// originating session's `TargetAddr` prepended so the caller can parse
    /// it exactly like the SS UDP path.
    pub async fn read_packet(&self) -> Result<Bytes> {
        self.core.read_packet().await
    }

    pub async fn close(&self) -> Result<()> {
        self.core.close().await
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn downgrade_latch_for_test(&self) -> bool {
        self.core.dial.downgrade_reported.load(Ordering::Acquire)
    }

    /// Test-only entry point that simulates the latch-reset path the mux
    /// runs whenever a per-target dial succeeds at the requested mode after
    /// a previous downgrade. Used by `vless_udp_mux_resets_downgrade_latch_*`
    /// to drive the recovery branch without standing up a server that can
    /// alternate between H3-up and H3-down on demand.
    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn force_reset_downgrade_latch_for_test(&self) {
        self.core.dial.downgrade_reported.store(false, Ordering::Release);
    }

    /// Test-only delegate: the downgrade-latch tests drive per-target
    /// dials directly, without the SOCKS5 framing `send_packet` needs.
    /// Gated like its only callers (`vless_udp_mux_*` in the crate test
    /// module are `feature = "metrics"`), so a default-feature clippy
    /// pass does not see it as dead code.
    #[cfg(all(test, feature = "metrics"))]
    pub(crate) async fn session_for(
        &self,
        target: &TargetAddr,
    ) -> Result<Arc<VlessUdpMuxSessionEntry<VlessUdpWsTransport>>> {
        self.core.session_for(target).await
    }
}
