use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Notify, mpsc};

use super::super::resumption::{ParkedMuxSubKind, ParkedVlessMux};

use crate::metrics::{Metrics, Protocol};

mod frames;
mod state;
mod tcp_sub;
mod udp_sub;

pub(in crate::server::transport) use frames::handle_client_bytes;
pub(in crate::server::transport) use state::{MuxAccounting, MuxRouteCtx, MuxServerCtx, MuxState};

use state::{MuxSubConn, SubConnKind, client_metrics};

/// Re-attaches a parked mux into a freshly-started client stream.
///
/// Re-spawns one reader task per sub-connection against the supplied
/// outbound channel (cloned once per task) and restores the partial
/// frame buffer that was preserved at park time. Returns the live
/// [`MuxState`] ready to be installed in `UpstreamSession::Mux`.
///
/// **Total over the bundle**: every entry in `parked.sub_conns` becomes a live
/// sub-connection, and none of them can fail — a `ParkedMuxSubKind` already
/// carries both halves of its upstream, so nothing is reopened and nothing is
/// dialled. That is what lets a caller decide *once*, before it consumes the
/// park, whether the whole bundle can be served: there is no partial outcome
/// below this call. See `transport::mesh_relay`'s `splice_plaintext_vless_mux`,
/// which relies on it to refuse a bundle whole rather than half-splice it.
///
/// `accounting` says whether this node counts the session's client-facing
/// traffic; a relayed mux passes [`MuxAccounting::OnTheEdge`], because the edge
/// that terminates the client carrier already counts the whole frame stream.
pub(in crate::server::transport) fn attach_parked<Msg>(
    parked: ParkedVlessMux,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    metrics: &Arc<Metrics>,
    protocol: Protocol,
    accounting: MuxAccounting,
) -> MuxState
where
    Msg: Send + 'static,
{
    let client = client_metrics(accounting, metrics, &parked.user_counters);
    let mut mux = MuxState::new(parked.user, Arc::clone(&parked.user_counters), accounting);
    mux.buffer = parked.buffer;
    for (id, parked_sub) in parked.sub_conns {
        let cancel = Arc::new(Notify::new());
        let cancel_for_task = Arc::clone(&cancel);
        match parked_sub.kind {
            ParkedMuxSubKind::Tcp { writer, reader } => {
                let task = tokio::spawn(tcp_sub::run_tcp_reader(
                    id,
                    reader,
                    tx.clone(),
                    make_binary,
                    client.clone(),
                    protocol,
                    cancel_for_task,
                ));
                mux.sub_conns.insert(
                    id,
                    MuxSubConn {
                        kind: SubConnKind::Tcp(writer),
                        cancel,
                        reader_task: Some(task),
                    },
                );
            },
            ParkedMuxSubKind::Udp { socket, default_target } => {
                let reader_socket = Arc::clone(&socket);
                let task = tokio::spawn(udp_sub::run_udp_reader(
                    id,
                    reader_socket,
                    tx.clone(),
                    make_binary,
                    client.clone(),
                    protocol,
                    cancel_for_task,
                ));
                mux.sub_conns.insert(
                    id,
                    MuxSubConn {
                        kind: SubConnKind::Udp { socket, default_target },
                        cancel,
                        reader_task: Some(task),
                    },
                );
            },
        }
    }
    mux
}
