use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::{
    clock,
    crypto::encrypt_udp_packet_for_response,
    metrics::{Metrics, PerUserCounters, Protocol},
    protocol::TargetAddr,
};

use super::super::constants::MAX_UDP_PAYLOAD_SIZE;
use super::super::scratch::UdpRecvBuf;
use super::entry::{ActiveSlot, UdpResponseCoding, UdpResponseSender};

pub(super) struct NatReaderCtx {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) active: Arc<ActiveSlot>,
    /// Accounting identity of the entry's owner. The *key* material a response
    /// is sealed with is not here but on the attachment
    /// ([`UdpResponseCoding::Ss`]), because a v5 relayed carrier attaches to
    /// this same socket with no key at all.
    pub(super) user_id: Arc<str>,
    pub(super) target: SocketAddr,
    pub(super) server_session_id: Option<[u8; 8]>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) user_counters: Arc<PerUserCounters>,
    pub(super) last_active: Arc<AtomicU64>,
    pub(super) next_packet_id: Arc<AtomicU64>,
}

pub(super) async fn nat_reader_task(ctx: NatReaderCtx) {
    let NatReaderCtx {
        socket,
        active,
        user_id,
        target,
        server_session_id,
        metrics,
        user_counters,
        last_active,
        next_packet_id,
    } = ctx;
    let mut moved = active.subscribe();

    loop {
        if let Err(error) = socket.readable().await {
            warn!(%target, %error, "UDP NAT socket readiness error, closing reader");
            break;
        }
        // Allocate from the pool only once a datagram is ready, so an idle
        // NAT session holds no per-session receive buffer; the buffer returns
        // to the pool before the next park.
        let mut buf = UdpRecvBuf::take();
        let (n, source) = match socket.try_recv_from(&mut buf) {
            Ok(v) => v,
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => {
                warn!(%target, %error, "UDP NAT socket recv error, closing reader");
                break;
            },
        };

        // Snapshot the active session so encoding picks up the latest
        // client_session_id after a reconnect — or the plaintext coding after a
        // v5 relayed carrier took the slot over.
        // Seen before the slot is read: a re-point after this read is
        // signalled to the send wait below.
        moved.borrow_and_update();
        let (sender, coding) = match active.snapshot() {
            Some(snapshot) => snapshot,
            None => {
                // Intentionally do NOT touch last_active here: otherwise a
                // chatty upstream keeps the entry (and its socket + reader
                // task) alive forever after the client has gone away.
                metrics.record_udp_nat_response_dropped();
                debug!(%target, "NAT response dropped: no active client session");
                continue;
            },
        };

        // Both arms produce the same body — `TargetAddr(source) || payload` —
        // and differ only in who seals it. The SS-2022 packet counter advances
        // on the sealed arm alone: it numbers packets *within one AEAD session*,
        // and the plaintext arm opens none.
        let response = match &coding {
            UdpResponseCoding::Ss { user, session } => {
                let packet_id = next_packet_id.fetch_add(1, Ordering::Relaxed);
                match encrypt_udp_packet_for_response(
                    user,
                    &TargetAddr::from(source),
                    &buf[..n],
                    session,
                    server_session_id,
                    packet_id,
                ) {
                    Ok(v) => v,
                    Err(error) => {
                        warn!(%source, %error, "failed to encrypt NAT UDP response");
                        continue;
                    },
                }
            },
            // The edge seals this under the client's key; the home only wraps.
            UdpResponseCoding::Plaintext => match TargetAddr::from(source).to_wire_bytes() {
                Ok(mut wrapped) => {
                    wrapped.extend_from_slice(&buf[..n]);
                    wrapped
                },
                Err(error) => {
                    warn!(%source, %error, "failed to encode NAT UDP response target address");
                    continue;
                },
            },
        };

        if record_oversized_socket_response_drop(
            Some(&sender),
            metrics.as_ref(),
            &user_id,
            source,
            response.len(),
        ) {
            continue;
        }

        let protocol = sender.protocol();
        let app_protocol = sender.app_protocol();
        // Only the node that terminates the client session accounts the user's
        // bytes; see [`UdpResponseCoding::terminates_client_session`]. The
        // coding is read from the same snapshot as the sender, so a socket that
        // changes hands between a decrypting carrier and a relayed one accounts
        // each response under whichever owns it at that moment.
        if coding.terminates_client_session() {
            user_counters.udp_out(app_protocol, protocol).increment(n as u64);
            metrics.record_udp_response_datagrams(Arc::clone(&user_id), protocol, app_protocol, 1);
        }
        match send_until_moved(&sender, Bytes::from(response), &active, &mut moved).await {
            Some(true) => {
                // Only a delivered response resets the idle timer. Otherwise a
                // chatty upstream pointed at a dead client would hold the NAT
                // entry (and its socket + reader task) alive indefinitely.
                last_active.store(clock::current_unix_secs(), Ordering::Relaxed);
            },
            Some(false) => {
                debug!(%target, "NAT response dropped: client session disconnected");
            },
            None => {
                metrics.record_udp_nat_response_dropped();
                debug!(%target, "NAT response dropped: the session moved to another carrier");
            },
        }
    }
}

/// Hands `response` to `sender`, waiting with the sender's own backpressure —
/// but only while the slot still leads to `sender`'s carrier. A resume or
/// reconnect that re-points the slot (or a detach that empties it) ends the
/// wait: the carrier being waited on may be one the client no longer reads, and
/// waiting on it would hold every later response away from the carrier that
/// replaced it. The response in flight is then dropped (`None`) — it was sealed
/// for the old attachment's coding — and the next one goes to the new sender.
pub(super) async fn send_until_moved(
    sender: &UdpResponseSender,
    response: Bytes,
    active: &ActiveSlot,
    moved: &mut watch::Receiver<()>,
) -> Option<bool> {
    let send = sender.send_bytes(response);
    tokio::pin!(send);
    loop {
        tokio::select! {
            biased;
            delivered = &mut send => return Some(delivered),
            changed = moved.changed() => {
                // `Err`: the entry is gone (its reader is being aborted). A
                // change that kept the path (signalled, then re-pointed back)
                // keeps waiting.
                if changed.is_err() || !active.leads_to(sender) {
                    return None;
                }
            },
        }
    }
}

pub(crate) fn record_oversized_socket_response_drop(
    sender: Option<&UdpResponseSender>,
    metrics: &Metrics,
    user_id: &Arc<str>,
    source: SocketAddr,
    encoded_len: usize,
) -> bool {
    if !matches!(sender.map(UdpResponseSender::protocol), Some(Protocol::Socket))
        || encoded_len <= MAX_UDP_PAYLOAD_SIZE
    {
        return false;
    }

    metrics.record_udp_oversized_datagram_dropped(
        Arc::clone(user_id),
        Protocol::Socket,
        sender
            .map(UdpResponseSender::app_protocol)
            .unwrap_or(crate::metrics::AppProtocol::Shadowsocks),
        "down",
    );
    warn!(
        user = %user_id,
        %source,
        encoded_bytes = encoded_len,
        max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
        "dropping oversized socket udp response datagram"
    );
    true
}
