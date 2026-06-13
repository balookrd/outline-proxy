//! UDP egress over a reverse-tunnel peer carrier (topology A).
//!
//! Parallel to [`super::group::GroupUdpContext`] but without the uplink
//! manager / failover machinery: a reverse peer is a single pinned carrier.
//! The framing matches the peer's protocol:
//!
//! - **SS**: one [`UdpWsTransport`] over the carrier's QUIC datagram channel
//!   carries every datagram (`target_wire || payload`), one downlink task
//!   pumps replies back.
//! - **VLESS**: one [`VlessUdpQuicSession`] per target (session-id muxed on
//!   the carrier), opened on demand; a per-session downlink task pumps its
//!   replies. The session payload carries no target — it is bound to the
//!   session — so the downlink stamps the target it opened.
//!
//! The peer's `ss` server already runs its half of the pump, so only this
//! client half is new.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use outline_metrics as metrics;
use outline_transport::quic::SharedQuicConnection;
use outline_transport::{
    UdpWsTransport, VlessUdpQuicSession, ss_udp_over_connection, vless_udp_over_connection,
};
use socks5_proto::TargetAddr;

use super::group::UdpResponse;
use crate::reverse::{ReversePeer, ReversePeerCreds};

/// Per-association UDP egress over one reverse peer, framed per its protocol.
pub(super) enum ReverseUdpAssoc {
    Ss(SsReverseUdp),
    Vless(VlessReverseUdp),
}

impl ReverseUdpAssoc {
    /// Build the egress for `peer` and spawn its downlink pump(s). `responses`
    /// is the shared association writer channel; `tasks` owns the SS downlink
    /// task (VLESS spawns one detached pump per opened session instead).
    pub(super) fn open(
        peer: &Arc<ReversePeer>,
        group_name: Arc<str>,
        responses: mpsc::Sender<UdpResponse>,
        tasks: &Mutex<JoinSet<()>>,
    ) -> Result<Self> {
        match &peer.creds {
            ReversePeerCreds::Ss { cipher, password, .. } => {
                let transport = Arc::new(ss_udp_over_connection(
                    Arc::clone(&peer.conn),
                    *cipher,
                    password,
                    "reverse_udp",
                )?);
                let downlink = Arc::clone(&transport);
                let group = Arc::clone(&group_name);
                let label = Arc::clone(&peer.label);
                tasks.lock().expect("reverse udp tasks poisoned").spawn(async move {
                    loop {
                        let payload = match downlink.read_packet().await {
                            Ok(payload) => payload,
                            Err(_) => return,
                        };
                        // Each datagram is `target_wire || app_payload`.
                        let Ok((target, consumed)) = TargetAddr::from_wire_bytes(&payload) else {
                            continue;
                        };
                        if responses
                            .send(UdpResponse {
                                target,
                                payload: payload.slice(consumed..),
                                group_name: Arc::clone(&group),
                                uplink_name: Arc::clone(&label),
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
                Ok(Self::Ss(SsReverseUdp {
                    transport,
                    group_name,
                    peer_label: Arc::clone(&peer.label),
                }))
            },
            ReversePeerCreds::Vless { uuid } => Ok(Self::Vless(VlessReverseUdp {
                conn: Arc::clone(&peer.conn),
                uuid: *uuid,
                group_name,
                peer_label: Arc::clone(&peer.label),
                responses,
                sessions: Mutex::new(HashMap::new()),
            })),
        }
    }

    /// Send one UDP packet to `target`. `payload` is the application payload
    /// (no target prefix); SS-framing prepends the target wire form, VLESS
    /// routes it to the target's session.
    pub(super) async fn send_packet(&self, target: &TargetAddr, payload: &[u8]) -> Result<()> {
        match self {
            Self::Ss(s) => s.send(target, payload).await,
            Self::Vless(v) => v.send(target, payload).await,
        }
    }
}

/// SS-UDP: one datagram transport for the whole association; the target rides
/// inside each datagram.
pub(super) struct SsReverseUdp {
    transport: Arc<UdpWsTransport>,
    group_name: Arc<str>,
    peer_label: Arc<str>,
}

impl SsReverseUdp {
    async fn send(&self, target: &TargetAddr, payload: &[u8]) -> Result<()> {
        let mut datagram = target.to_wire_bytes()?;
        datagram.extend_from_slice(payload);
        self.transport.send_packet(&datagram).await?;
        metrics::add_udp_datagram("client_to_upstream", &self.group_name, &self.peer_label);
        metrics::add_bytes(
            "udp",
            "client_to_upstream",
            &self.group_name,
            &self.peer_label,
            datagram.len(),
        );
        Ok(())
    }
}

/// VLESS-UDP: one session per target, session-id muxed on the carrier. Each
/// session's downlink is pumped by a detached task, aborted on drop.
pub(super) struct VlessReverseUdp {
    conn: Arc<SharedQuicConnection>,
    uuid: [u8; 16],
    group_name: Arc<str>,
    peer_label: Arc<str>,
    responses: mpsc::Sender<UdpResponse>,
    sessions: Mutex<HashMap<TargetAddr, SessionEntry>>,
}

struct SessionEntry {
    session: Arc<VlessUdpQuicSession>,
    pump: JoinHandle<()>,
}

impl Drop for VlessReverseUdp {
    fn drop(&mut self) {
        for entry in self
            .sessions
            .lock()
            .expect("reverse vless udp sessions poisoned")
            .values()
        {
            entry.pump.abort();
        }
    }
}

impl VlessReverseUdp {
    async fn send(&self, target: &TargetAddr, payload: &[u8]) -> Result<()> {
        let session = self.session_for(target).await?;
        session.send_packet(payload).await?;
        metrics::add_udp_datagram("client_to_upstream", &self.group_name, &self.peer_label);
        metrics::add_bytes(
            "udp",
            "client_to_upstream",
            &self.group_name,
            &self.peer_label,
            payload.len(),
        );
        Ok(())
    }

    /// Return the existing session for `target` or open a fresh one and spawn
    /// its downlink pump. A rare concurrent open for the same target keeps the
    /// first inserted session and discards the loser.
    async fn session_for(&self, target: &TargetAddr) -> Result<Arc<VlessUdpQuicSession>> {
        if let Some(entry) = self.sessions.lock().expect("poisoned").get(target) {
            return Ok(Arc::clone(&entry.session));
        }
        let session =
            Arc::new(vless_udp_over_connection(Arc::clone(&self.conn), &self.uuid, target).await?);

        let pump_session = Arc::clone(&session);
        let responses = self.responses.clone();
        let group = Arc::clone(&self.group_name);
        let label = Arc::clone(&self.peer_label);
        let target_for_pump = target.clone();
        let pump = tokio::spawn(async move {
            loop {
                let payload = match pump_session.read_packet().await {
                    Ok(payload) => payload,
                    Err(_) => return,
                };
                // VLESS-UDP payload carries no target — it is the session's.
                if responses
                    .send(UdpResponse {
                        target: target_for_pump.clone(),
                        payload,
                        group_name: Arc::clone(&group),
                        uplink_name: Arc::clone(&label),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        });

        let mut sessions = self.sessions.lock().expect("poisoned");
        if let Some(entry) = sessions.get(target) {
            // Lost the race — another task opened first; drop ours.
            pump.abort();
            return Ok(Arc::clone(&entry.session));
        }
        sessions.insert(target.clone(), SessionEntry { session: Arc::clone(&session), pump });
        Ok(session)
    }
}
