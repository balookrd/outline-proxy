//! SS-UDP over a reverse-tunnel peer carrier (topology A).
//!
//! Parallel to [`super::group::GroupUdpContext`] but without the uplink
//! manager / failover machinery: a reverse peer is a single pinned carrier,
//! so one [`UdpWsTransport`] over its QUIC datagram channel carries every
//! datagram for the association, and one downlink task pumps replies back.
//! The peer's `ss` server already runs its half of the datagram pump
//! (spawned inside `handle_raw_ss_connection`), so only this client half is
//! new.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use outline_metrics as metrics;
use outline_transport::{UdpWsTransport, ss_udp_over_connection};
use socks5_proto::TargetAddr;

use super::group::UdpResponse;
use crate::reverse::ReversePeer;

/// Per-association SS-UDP transport bound to one reverse peer. Holds the
/// datagram transport for the send path plus the group/peer labels for the
/// `client_to_upstream` counters; the downlink task is owned by the caller's
/// `JoinSet`.
pub(super) struct ReverseUdpAssoc {
    transport: Arc<UdpWsTransport>,
    group_name: Arc<str>,
    peer_label: Arc<str>,
}

impl ReverseUdpAssoc {
    /// Open the SS-UDP transport over `peer`'s carrier and spawn the downlink
    /// pump into `tasks`. `responses` is the shared association writer channel.
    pub(super) fn open(
        peer: &Arc<ReversePeer>,
        group_name: Arc<str>,
        responses: mpsc::Sender<UdpResponse>,
        tasks: &Mutex<JoinSet<()>>,
    ) -> Result<Self> {
        let transport = Arc::new(ss_udp_over_connection(
            Arc::clone(&peer.conn),
            peer.cipher,
            &peer.password,
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

        Ok(Self {
            transport,
            group_name,
            peer_label: Arc::clone(&peer.label),
        })
    }

    /// Send one `target_wire || payload` datagram to the peer. Counted like
    /// the group path (`GroupUdpContext::send_packet`): only after a
    /// successful send, with the peer label in the uplink slot — the same
    /// labels the downlink pump stamps on `UdpResponse`.
    pub(super) async fn send_packet(&self, payload: &[u8]) -> Result<()> {
        self.transport.send_packet(payload).await?;
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
}
