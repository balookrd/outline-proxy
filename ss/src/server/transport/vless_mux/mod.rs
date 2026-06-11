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
pub(in crate::server::transport) use state::{MuxRouteCtx, MuxServerCtx, MuxState};

use state::{MuxSubConn, SubConnKind};

/// Re-attaches a parked mux into a freshly-started client stream.
///
/// Re-spawns one reader task per sub-connection against the supplied
/// outbound channel (cloned once per task) and restores the partial
/// frame buffer that was preserved at park time. Returns the live
/// [`MuxState`] ready to be installed in `UpstreamSession::Mux`.
pub(in crate::server::transport) fn attach_parked<Msg>(
    parked: ParkedVlessMux,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
) -> MuxState
where
    Msg: Send + 'static,
{
    let user_label = parked.user.label_arc();
    let mut mux = MuxState::new(parked.user, Arc::clone(&parked.user_counters));
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
                    Arc::clone(&metrics),
                    protocol,
                    Arc::clone(&user_label),
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
                    Arc::clone(&metrics),
                    protocol,
                    Arc::clone(&user_label),
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
