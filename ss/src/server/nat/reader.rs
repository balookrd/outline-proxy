use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use tokio::{net::UdpSocket, sync::Mutex};
use tracing::{debug, warn};

use crate::{
    clock,
    crypto::{UserKey, encrypt_udp_packet_for_response},
    metrics::{Metrics, Protocol},
    protocol::TargetAddr,
};

use super::super::constants::MAX_UDP_PAYLOAD_SIZE;
use super::entry::{ActiveSession, UdpResponseSender};

pub(super) struct NatReaderCtx {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) active: Arc<Mutex<Option<ActiveSession>>>,
    pub(super) user: UserKey,
    pub(super) target: SocketAddr,
    pub(super) server_session_id: Option<[u8; 8]>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) last_active: Arc<AtomicU64>,
    pub(super) next_packet_id: Arc<AtomicU64>,
}

pub(super) async fn nat_reader_task(ctx: NatReaderCtx) {
    let NatReaderCtx {
        socket,
        active,
        user,
        target,
        server_session_id,
        metrics,
        last_active,
        next_packet_id,
    } = ctx;

    let user_id = user.id_arc();
    let user_counters = metrics.user_counters(&user_id);
    let mut buf = vec![0u8; MAX_UDP_PAYLOAD_SIZE];
    loop {
        let (n, source) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(error) => {
                warn!(%target, %error, "UDP NAT socket recv error, closing reader");
                break;
            },
        };

        // Snapshot the active session so encryption picks up the latest
        // client_session_id after a reconnect.
        let (sender, session) = match active.lock().await.as_ref() {
            Some(a) => (a.sender.clone(), a.session.clone()),
            None => {
                // Intentionally do NOT touch last_active here: otherwise a
                // chatty upstream keeps the entry (and its socket + reader
                // task) alive forever after the client has gone away.
                metrics.record_udp_nat_response_dropped();
                debug!(%target, "NAT response dropped: no active client session");
                continue;
            },
        };

        let packet_id = next_packet_id.fetch_add(1, Ordering::Relaxed);
        let ciphertext = match encrypt_udp_packet_for_response(
            &user,
            &TargetAddr::Socket(source),
            &buf[..n],
            &session,
            server_session_id,
            packet_id,
        ) {
            Ok(v) => v,
            Err(error) => {
                warn!(%source, %error, "failed to encrypt NAT UDP response");
                continue;
            },
        };

        if record_oversized_socket_response_drop(
            Some(&sender),
            metrics.as_ref(),
            &user,
            source,
            ciphertext.len(),
        ) {
            continue;
        }

        let protocol = sender.protocol();
        user_counters.udp_out(protocol).increment(n as u64);
        metrics.record_udp_response_datagrams(Arc::clone(&user_id), protocol, 1);
        if sender.send_bytes(Bytes::from(ciphertext)).await {
            // Only a delivered response resets the idle timer. Otherwise a
            // chatty upstream pointed at a dead client would hold the NAT
            // entry (and its socket + reader task) alive indefinitely.
            last_active.store(clock::current_unix_secs(), Ordering::Relaxed);
        } else {
            debug!(%target, "NAT response dropped: client session disconnected");
        }
    }
}

pub(crate) fn record_oversized_socket_response_drop(
    sender: Option<&UdpResponseSender>,
    metrics: &Metrics,
    user: &UserKey,
    source: SocketAddr,
    ciphertext_len: usize,
) -> bool {
    if !matches!(sender.map(UdpResponseSender::protocol), Some(Protocol::Socket))
        || ciphertext_len <= MAX_UDP_PAYLOAD_SIZE
    {
        return false;
    }

    metrics.record_udp_oversized_datagram_dropped(
        user.id_arc(),
        Protocol::Socket,
        "target_to_client",
    );
    warn!(
        user = user.id(),
        %source,
        encrypted_bytes = ciphertext_len,
        max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
        "dropping oversized socket udp response datagram"
    );
    true
}
