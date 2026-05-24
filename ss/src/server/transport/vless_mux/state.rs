use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::BytesMut;
use tokio::{
    net::{
        UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Notify,
    task::JoinHandle,
};
use tracing::debug;

use super::super::super::{
    dns_cache::DnsCache,
    resumption::{ParkedMuxSubConn, ParkedMuxSubKind, ParkedVlessMux},
};

use crate::{
    metrics::{Metrics, PerUserCounters, Protocol},
    outbound::OutboundIpv6,
    protocol::vless::VlessUser,
};

/// Maximum number of concurrent mux sub-connections per VLESS session.
/// Matches xray-core's default `Concurrency=8`.
pub(in crate::server::transport) const MAX_MUX_SUB_CONNS: usize = 8;

pub(in crate::server::transport) struct MuxServerCtx {
    pub dns_cache: Arc<DnsCache>,
    pub prefer_ipv4_upstream: bool,
    pub outbound_ipv6: Option<Arc<OutboundIpv6>>,
    pub metrics: Arc<Metrics>,
}

pub(in crate::server::transport) struct MuxRouteCtx {
    pub protocol: Protocol,
    pub path: Arc<str>,
}

pub(in crate::server::transport) struct MuxState {
    pub(super) sub_conns: HashMap<u16, MuxSubConn>,
    pub(super) buffer: BytesMut,
    pub(super) user: VlessUser,
    pub(super) user_counters: Arc<PerUserCounters>,
}

/// Output of a sub-connection reader task. Distinguishes the natural
/// EOF / closed path (no harvest possible) from a caller-requested
/// cancel where the underlying reader half (TCP only) is returned for
/// re-attach inside an [`OrphanRegistry`].
pub(super) enum MuxReaderHarvest {
    /// Reader returned naturally — upstream EOF or send-error on the
    /// outbound channel. The reader is consumed.
    Closed,
    /// Caller fired `cancel.notify_one()` before EOF and the TCP
    /// reader half was harvested. Only TCP sub-connections produce
    /// this variant; UDP sub-conns share the socket via `Arc` and
    /// have nothing to hand off.
    TcpCancelled(OwnedReadHalf),
    /// UDP cancel: nothing to harvest (the socket already lives in
    /// the parent `SubConnKind::Udp`). Distinct variant rather than
    /// reusing `Closed` so the harvest path can tell "loop exited
    /// because we asked it to" from "loop exited because the channel
    /// died on its own".
    UdpCancelled,
}

pub(super) struct MuxSubConn {
    pub(super) kind: SubConnKind,
    /// Notify used to ask the reader task to stop and (for TCP) hand
    /// over its read half. Cloned by the spawn site; calling
    /// `notify_one()` once is enough — the task selects on it.
    pub(super) cancel: Arc<Notify>,
    /// Reader task handle. `None` after [`MuxSubConn::take_reader_task`]
    /// has moved it out (park path). On drop the leftover `Some` is
    /// aborted as a safety net, mirroring the previous `AbortOnDrop`.
    pub(super) reader_task: Option<JoinHandle<MuxReaderHarvest>>,
}

impl Drop for MuxSubConn {
    fn drop(&mut self) {
        // Safety net for `?`-return / panic paths inside `MuxState`.
        // Mirrors the previous `AbortOnDrop` behaviour so a UDP reader
        // (which would otherwise block on `recv_from` forever) does
        // not survive the parent `MuxState`. Cleanup paths that need
        // to keep the task alive go through [`Self::into_parts`].
        if let Some(handle) = self.reader_task.take() {
            handle.abort();
        }
    }
}

impl MuxSubConn {
    /// Decomposes the sub-conn into its three pieces, suppressing the
    /// auto-abort. The caller takes responsibility for the reader
    /// task's lifecycle and the writer/socket cleanup.
    ///
    /// Used by both [`MuxState::shutdown`] and
    /// [`MuxState::harvest_into_parked`]; the alternative — an
    /// `Option<SubConnKind>` field — would force the hot
    /// `dispatch_frame` path through extra unwraps for no benefit.
    pub(super) fn into_parts(
        self,
    ) -> (SubConnKind, Option<JoinHandle<MuxReaderHarvest>>, Arc<Notify>) {
        let me = std::mem::ManuallyDrop::new(self);
        // SAFETY: `me` is wrapped in ManuallyDrop so its `Drop` impl
        // does not run; each field is therefore read out exactly once
        // and then ownership transfers to the returned tuple.
        unsafe {
            let kind = std::ptr::read(&me.kind);
            let task = std::ptr::read(&me.reader_task);
            let cancel = std::ptr::read(&me.cancel);
            (kind, task, cancel)
        }
    }
}

pub(super) enum SubConnKind {
    Tcp(OwnedWriteHalf),
    Udp {
        socket: Arc<UdpSocket>,
        default_target: SocketAddr,
    },
}

impl MuxState {
    pub fn new(user: VlessUser, user_counters: Arc<PerUserCounters>) -> Self {
        Self {
            sub_conns: HashMap::new(),
            buffer: BytesMut::new(),
            user,
            user_counters,
        }
    }

    pub async fn shutdown(&mut self) {
        use tokio::io::AsyncWriteExt;

        // Drain shuts down each TCP write half gracefully so the upstream
        // reader sees EOF, then aborts every reader task. UDP readers
        // would otherwise sit in `recv_from` forever — they have no
        // shutdown signal at the socket level.
        for (_, sub) in self.sub_conns.drain() {
            let (kind, task, _cancel) = sub.into_parts();
            if let SubConnKind::Tcp(mut w) = kind {
                let _ = w.shutdown().await;
            }
            if let Some(handle) = task {
                handle.abort();
            }
        }
    }

    /// Atomically harvests every sub-connection's writer/socket and
    /// reader half into a [`ParkedVlessMux`] for the orphan registry.
    /// Each sub-conn's reader task is asked to stop via `cancel.notify_one()`,
    /// then awaited; TCP harvests yield the `OwnedReadHalf`, UDP
    /// harvests are handle-only.
    ///
    /// Sub-conns whose reader task already exited on its own
    /// (closed / cancelled before harvest, or panicked) are skipped:
    /// their writer/socket is dropped normally, and the
    /// post-condition becomes "park a possibly-pruned mux". Callers
    /// that need an all-or-nothing guarantee should consult
    /// [`Self::is_parkable`] first.
    pub async fn harvest_into_parked(mut self, owner: Arc<str>) -> ParkedVlessMux {
        let mut parked_subs = HashMap::with_capacity(self.sub_conns.len());
        for (id, sub) in self.sub_conns.drain() {
            let (kind, task, cancel) = sub.into_parts();
            cancel.notify_one();
            let task = match task {
                Some(t) => t,
                None => continue,
            };
            let harvest = task.await;
            let parked_kind = match (kind, harvest) {
                (SubConnKind::Tcp(writer), Ok(MuxReaderHarvest::TcpCancelled(reader))) => {
                    ParkedMuxSubKind::Tcp { writer, reader }
                },
                (
                    SubConnKind::Udp { socket, default_target },
                    Ok(MuxReaderHarvest::UdpCancelled),
                ) => ParkedMuxSubKind::Udp { socket, default_target },
                (_, Ok(MuxReaderHarvest::Closed)) => {
                    debug!(session_id = id, "mux sub-conn already closed; skipping for park");
                    continue;
                },
                (k, Ok(_other)) => {
                    debug!(
                        session_id = id,
                        kind_label = sub_conn_kind_label(&k),
                        "mux harvest type mismatch (cancel race?); skipping sub-conn"
                    );
                    continue;
                },
                (_, Err(error)) => {
                    debug!(session_id = id, error = %error, "mux reader task join failed; skipping for park");
                    continue;
                },
            };
            parked_subs.insert(id, ParkedMuxSubConn { kind: parked_kind });
        }
        ParkedVlessMux {
            sub_conns: parked_subs,
            buffer: self.buffer,
            user: self.user,
            owner,
            user_counters: self.user_counters,
        }
    }

    /// Returns `true` when there is at least one live sub-connection
    /// to preserve. Empty muxes are not worth a registry entry.
    pub fn is_parkable(&self) -> bool {
        !self.sub_conns.is_empty()
    }
}

pub(super) fn sub_conn_kind_label(kind: &SubConnKind) -> &'static str {
    match kind {
        SubConnKind::Tcp(_) => "tcp",
        SubConnKind::Udp { .. } => "udp",
    }
}
