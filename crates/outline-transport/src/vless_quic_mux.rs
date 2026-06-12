//! VLESS-UDP session mux over raw QUIC.
//!
//! Mirror of [`crate::vless::VlessUdpSessionMux`] but the per-target
//! sessions ride on [`crate::quic::vless_udp::VlessUdpQuicSession`]
//! over a shared QUIC connection. The connection-level demuxer
//! ([`crate::quic::vless_udp::VlessUdpDemuxer`]) takes care of routing
//! inbound datagrams by `session_id_4B_BE` to the right session, so
//! each target — like in the WS path — gets its own logical session
//! but they all share one QUIC connection (hence one TLS handshake,
//! one congestion-control state, etc.).
//!
//! The session map, janitor and downlink fan-in are the carrier-generic
//! [`crate::vless::udp_mux_core::VlessUdpMuxCore`] shared with the WS
//! mux; this module contributes only the QUIC dial path. Public API
//! matches the WS mux exactly:
//!
//! * `send_packet(socks5_payload)` — the SOCKS5 atyp prefix is parsed
//!   to pick / open a session; only the inner UDP payload crosses the
//!   wire.
//!
//! * `read_packet() -> Bytes` — downlink datagrams arrive prefixed
//!   with the originating session's SOCKS5 atyp / addr / port so the
//!   caller can use the same parser as the SS UDP path.

#![cfg(feature = "quic")]

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use socks5_proto::TargetAddr;
use url::Url;

use crate::quic::vless_udp::VlessUdpQuicSession;
use crate::quic_connect::connect_vless_udp_session_quic;
use crate::vless::VlessUdpMuxLimits;
use crate::vless::udp_mux_core::{VlessUdpMuxCore, VlessUdpMuxDial, VlessUdpMuxSession};
use crate::{DnsCache, TransportOperation, UplinkConnectionBinding};

impl VlessUdpMuxSession for VlessUdpQuicSession {
    async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        VlessUdpQuicSession::send_packet(self, payload).await
    }

    async fn read_packet(&self) -> Result<Bytes> {
        VlessUdpQuicSession::read_packet(self).await
    }

    async fn close(&self) -> Result<()> {
        VlessUdpQuicSession::close(self).await
    }
}

pub struct VlessUdpQuicMux {
    core: VlessUdpMuxCore<QuicVlessUdpDialer>,
}

/// Captured connection parameters used to open a new per-target VLESS UDP
/// session over the shared QUIC connection on demand.
struct QuicVlessUdpDialer {
    dns_cache: Arc<DnsCache>,
    url: Url,
    uuid: [u8; 16],
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
}

impl VlessUdpMuxDial for QuicVlessUdpDialer {
    type Session = VlessUdpQuicSession;

    async fn dial(&self, target: &TargetAddr) -> Result<Arc<VlessUdpQuicSession>> {
        let session = connect_vless_udp_session_quic(
            &self.dns_cache,
            &self.url,
            self.fwmark,
            self.ipv6_first,
            self.source,
            &self.uuid,
            target,
        )
        .await
        .with_context(|| TransportOperation::Connect {
            target: format!("vless udp quic session to {target}"),
        })?;
        Ok(Arc::new(session))
    }
}

impl VlessUdpQuicMux {
    pub fn new(
        dns_cache: Arc<DnsCache>,
        url: Url,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        limits: VlessUdpMuxLimits,
    ) -> Self {
        let dialer = QuicVlessUdpDialer {
            dns_cache,
            url,
            uuid,
            fwmark,
            ipv6_first,
            source,
        };
        Self {
            core: VlessUdpMuxCore::new(dialer, limits, "vless udp quic", source),
        }
    }

    /// Attribute the QUIC mux's lifetime guard to a concrete uplink so it
    /// participates in `outline_ws_rust_uplink_open_connections` and the
    /// matching close-classification counter alongside per-session lifetimes.
    /// Same constraints as [`crate::UdpWsTransport::with_uplink_binding`].
    pub fn with_uplink_binding(mut self, binding: UplinkConnectionBinding) -> Self {
        self.core.attach_uplink_binding(binding);
        self
    }

    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        self.core.send_packet(socks5_payload).await
    }

    pub async fn read_packet(&self) -> Result<Bytes> {
        self.core.read_packet().await
    }

    pub async fn close(&self) -> Result<()> {
        self.core.close().await
    }
}
