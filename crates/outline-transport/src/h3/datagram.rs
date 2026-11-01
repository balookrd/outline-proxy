// Client UDP over HTTP/3 datagrams (RFC 9297), bound to one request stream.
//
// A datagram carries exactly the bytes the stream would otherwise carry as one
// WebSocket Binary frame (or one xhttp UDP record), prefixed with the stream's
// quarter id. The stream channel stays alive underneath as the per-packet
// fallback: anything that does not fit the current datagram size, or fails to
// go out as a datagram, rides it instead, and the server may answer either way.

use std::sync::Arc;

use anyhow::{Result, bail};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{Mutex, watch};

use outline_metrics as metrics;
use outline_wire::h3_datagram::{DatagramRegistration, datagram_overhead, encode_datagram};

use crate::frame_io::{DatagramChannel, DatagramGate, PacketSource};

/// What a negotiated request stream needs to send and receive datagrams: the
/// QUIC connection it lives on, its quarter stream id (the datagram prefix)
/// and its slot in the connection's datagram demultiplexer.
pub(crate) struct H3DatagramBinding {
    pub(crate) connection: quinn::Connection,
    pub(crate) quarter_stream_id: u64,
    pub(crate) registration: DatagramRegistration,
}

/// [`DatagramChannel`] that sends each packet as an HTTP/3 datagram when it
/// fits and through `fallback` (the request stream's own channel) when it does
/// not, and receives from both.
pub(crate) struct H3DatagramChannel {
    connection: quinn::Connection,
    quarter_stream_id: u64,
    /// `None` once the demultiplexer queue ended (connection closed, or the id
    /// was registered again) or `close` ran. Behind a lock because receiving
    /// needs `&mut`; only `recv_datagram` and `close` take it.
    registration: Mutex<Option<DatagramRegistration>>,
    fallback: Arc<dyn DatagramChannel>,
    /// Set by `close`; wakes a receiver parked on the lock-holding select.
    closed: watch::Sender<bool>,
    /// While set and closed, every packet rides the stream ([`Self::with_gate`]).
    gate: Option<Arc<DatagramGate>>,
    transport: &'static str,
    proto: &'static str,
}

enum Inbound {
    /// `None`: the demultiplexer queue ended.
    Datagram(Option<Bytes>),
    Stream(Result<Option<Bytes>>),
    Closed,
}

impl H3DatagramChannel {
    /// `transport` is `"ws_h3"` or `"xhttp_h3"`, `proto` `"ss"` or `"vless"`
    /// (metric labels).
    pub(crate) fn new(
        binding: H3DatagramBinding,
        fallback: Arc<dyn DatagramChannel>,
        transport: &'static str,
        proto: &'static str,
    ) -> Self {
        let H3DatagramBinding {
            connection,
            quarter_stream_id,
            registration,
        } = binding;
        Self {
            connection,
            quarter_stream_id,
            registration: Mutex::new(Some(registration)),
            fallback,
            closed: watch::channel(false).0,
            gate: None,
            transport,
            proto,
        }
    }

    /// Keeps every outbound packet on the stream until the protocol above
    /// opens `gate` (see [`DatagramGate`]).
    pub(crate) fn with_gate(mut self, gate: Arc<DatagramGate>) -> Self {
        self.gate = Some(gate);
        self
    }
}

/// Next datagram of the registration; never resolves once it is gone, so the
/// select below then waits on the stream alone.
async fn next_registered(registration: &mut Option<DatagramRegistration>) -> Option<Bytes> {
    match registration {
        Some(registration) => registration.rx.recv().await,
        None => std::future::pending().await,
    }
}

#[async_trait]
impl DatagramChannel for H3DatagramChannel {
    async fn send_datagram(&self, data: Bytes) -> Result<()> {
        if *self.closed.borrow() {
            bail!("HTTP/3 datagram channel is closed");
        }
        let room = self.connection.max_datagram_size().unwrap_or(0);
        if self.gate.as_deref().is_none_or(DatagramGate::is_open)
            && datagram_overhead(self.quarter_stream_id) + data.len() <= room
            && self
                .connection
                .send_datagram(encode_datagram(self.quarter_stream_id, &data))
                .is_ok()
        {
            // Counts datagrams handed to quinn, which may still drop the oldest
            // one when its send buffer is full.
            metrics::record_udp_h3_datagram("up", self.transport, self.proto);
            return Ok(());
        }
        // Gate still closed, too large for the current datagram size, or the
        // send failed (too large after an MTU drop, or the peer stopped
        // accepting): use the stream.
        metrics::record_udp_h3_datagram_fallback("up", self.transport, self.proto);
        self.fallback.send_datagram(data).await
    }

    async fn recv_datagram(&self) -> Result<Option<Bytes>> {
        Ok(self.recv_datagram_with_source().await?.map(|(_, packet)| packet))
    }

    async fn recv_datagram_with_source(&self) -> Result<Option<(PacketSource, Bytes)>> {
        let mut closed = self.closed.subscribe();
        let mut registration = self.registration.lock().await;
        loop {
            // Every branch is cancel-safe, so the losers drop without losing a
            // packet: `mpsc::Receiver::recv` is, and so is the stream channel's
            // receive (it waits on a lock, then on an mpsc receive, and takes
            // the packet in the same poll that sees it).
            let inbound = tokio::select! {
                _ = closed.wait_for(|closed| *closed) => Inbound::Closed,
                datagram = next_registered(&mut registration) => Inbound::Datagram(datagram),
                stream = self.fallback.recv_datagram() => Inbound::Stream(stream),
            };
            // Unbiased above so neither source starves the other; a `close()`
            // that raced a ready packet still wins here, so nothing queued is
            // handed out after it.
            if *closed.borrow() {
                return Ok(None);
            }
            match inbound {
                Inbound::Closed => return Ok(None),
                Inbound::Datagram(Some(datagram)) => {
                    metrics::record_udp_h3_datagram("down", self.transport, self.proto);
                    return Ok(Some((PacketSource::Datagram, datagram)));
                },
                // The connection stopped delivering datagrams. Not the end of
                // the session: the stream still carries it.
                Inbound::Datagram(None) => *registration = None,
                Inbound::Stream(Ok(Some(packet))) => {
                    metrics::record_udp_h3_datagram_fallback("down", self.transport, self.proto);
                    return Ok(Some((PacketSource::Stream, packet)));
                },
                // The stream is the session: its end or failure ends the channel.
                Inbound::Stream(Ok(None)) => return Ok(None),
                Inbound::Stream(Err(error)) => return Err(error),
            }
        }
    }

    async fn close(&self) {
        // First, so a receiver holding the registration lock lets it go.
        self.closed.send_replace(true);
        self.fallback.close().await;
        self.registration.lock().await.take();
    }
}

#[cfg(test)]
#[path = "tests/datagram.rs"]
mod tests;
