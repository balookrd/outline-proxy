//! Build a [`SharedQuicConnection`] from a carrier that was *accepted*
//! (reverse-tunnel, topology A) rather than dialed.
//!
//! Mirrors the field init of `dial::connect_quic_connection` minus the
//! dial/cache machinery: there is no `ConnectionKey` and no registry, so
//! nothing to invalidate on close. Liveness still works because
//! [`SharedQuicConnection::is_open`] consults `connection.close_reason()`
//! directly — the reverse-peer registry evicts a peer the moment its
//! carrier drops. The driver task here only emits a close-classification
//! log line for observability.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tokio::sync::OnceCell;
use tracing::info;

use super::connection::SharedQuicConnection;
use crate::AbortOnDrop;

/// Monotonic id for accepted reverse carriers, for log correlation. Distinct
/// from the dial-side registry ids; both only ever appear in logs.
static REVERSE_CONN_ID: AtomicU64 = AtomicU64::new(0);

/// Wrap an accepted `quinn::Connection` (and the server endpoint that
/// produced it, kept alive) in a [`SharedQuicConnection`] usable by the
/// per-session pipeline exactly as a dialed one. The negotiated ALPN is
/// read from the TLS handshake data so `supports_oversize_stream` works.
pub fn shared_connection_from_accepted(
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
) -> Arc<SharedQuicConnection> {
    let id = REVERSE_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let negotiated_alpn = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .unwrap_or_default();

    let peer = connection.remote_address();
    let connection_for_driver = connection.clone();
    let driver_task = AbortOnDrop::new(tokio::spawn(async move {
        let reason = connection_for_driver.closed().await;
        info!(
            target: "outline_transport::conn_life",
            id, %peer, mode = "quic-reverse",
            "reverse carrier closed: {reason}"
        );
    }));

    Arc::new(SharedQuicConnection {
        id,
        endpoint,
        connection,
        closed: AtomicBool::new(false),
        sessions_opened: Arc::new(AtomicU64::new(0)),
        vless_udp_demuxer: OnceCell::new(),
        negotiated_alpn,
        oversize_stream: OnceCell::new(),
        _driver_task: driver_task,
    })
}
