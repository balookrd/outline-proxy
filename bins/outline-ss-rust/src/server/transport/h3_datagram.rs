//! SS-UDP and VLESS-UDP over HTTP/3 DATAGRAM (RFC 9297) on an HTTP/3 request
//! stream.
//!
//! A session agrees datagrams on its anchor request (`x-outline-udp-datagram:
//! 1` both ways): the CONNECT of a `ws_h3` stream, or the GET (packet-up) /
//! the single POST (stream-one) of an `xhttp_h3` session. From then on every SS
//! packet that fits rides one QUIC datagram `varint(quarter_stream_id) ||
//! bytes`, where `bytes` is exactly what one WS Binary frame would carry (the
//! padded frame on a padded path) — on xhttp *without* the `len || payload`
//! UDP record framing the stream needs, since a datagram already has a
//! boundary. Anything that does not fit, or fails to send, falls back to the
//! stream, packet by packet; the stream stays the session's anchor and its end
//! is the session's end.
//!
//! VLESS-UDP rides the same anchors with two differences. A datagram carries
//! one VLESS-UDP record (`len || payload`, the stream's own framing, padded as a
//! Binary message would be), and the VLESS command, known only once the request
//! header has been read off the stream, decides whether the route is used at
//! all: a plain UDP session uses it, any other command declines it
//! ([`LinkPolicy`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use axum::http::{HeaderMap, HeaderValue};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use outline_wire::h3_datagram::{DatagramRegistration, datagram_overhead, encode_datagram};
use outline_wire::padding::PaddingScheme;
use outline_wire::xhttp::UDP_DATAGRAM_HEADER;
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::carrier_padding;
use super::throughput_monitor::ThroughputMonitor;
use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::constants::H3_DATAGRAM_BUFFER_BYTES;
use crate::server::nat::{ResponseSender, UdpResponseSender};

/// `proto` label of the SS-UDP datagram counters.
pub(in crate::server) const SS_PROTO_LABEL: &str = "ss";
/// `proto` label of the VLESS-UDP datagram counters.
pub(in crate::server) const VLESS_PROTO_LABEL: &str = "vless";

/// Count of downlink datagrams a stream has sent, shared with its WS writer.
/// Datagrams bypass the writer, so its idle cover timer reads this to tell a
/// live downlink from a quiet one: cover goes on the stream only when neither
/// stream frames nor datagrams went out for a whole gap.
#[derive(Default)]
pub(in crate::server) struct DatagramActivity(AtomicU64);

impl DatagramActivity {
    pub(in crate::server) fn note_send(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub(in crate::server) fn sends(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Whether a request offers UDP over HTTP/3 datagrams (`x-outline-udp-datagram:
/// 1`).
pub(in crate::server) fn offers_udp_datagrams(headers: &HeaderMap) -> bool {
    headers.get(UDP_DATAGRAM_HEADER).and_then(|v| v.to_str().ok()) == Some("1")
}

/// Confirms UDP over HTTP/3 datagrams in a response. Only called once the
/// stream is registered, so an absent header keeps the response as before.
pub(in crate::server) fn apply_udp_datagram_echo(headers: &mut HeaderMap) {
    headers.insert(UDP_DATAGRAM_HEADER, HeaderValue::from_static("1"));
}

/// The datagram side of one agreed request stream: the QUIC connection to send
/// on, the stream's quarter id, and the demux registration that receives the
/// client's datagrams for it (unregistered when dropped).
pub(in crate::server) struct H3DatagramRoute {
    pub(in crate::server) connection: quinn::Connection,
    pub(in crate::server) quarter_stream_id: u64,
    pub(in crate::server) registration: DatagramRegistration,
}

/// Where downlink datagrams go: the anchor stream's connection and quarter id.
pub(in crate::server) struct DatagramPeer {
    pub(in crate::server) connection: quinn::Connection,
    pub(in crate::server) quarter_stream_id: u64,
}

/// The current downlink target of a relay, shared between the relay (which
/// swaps it when the anchor changes) and its [`DatagramResponseSender`].
/// Empty while no anchor has agreed datagrams; every packet then rides the
/// stream exactly as on a session that never offered them.
pub(in crate::server) type DatagramTarget = ArcSwapOption<DatagramPeer>;

/// A change of a relay's datagram anchor.
pub(in crate::server) enum AnchorUpdate {
    /// A request stream agreed datagrams and is now the session's anchor.
    Attach(H3DatagramRoute),
    /// The anchor request ended; packets ride the stream until the next one.
    Detach,
}

/// Hands datagram routes to an SS-UDP relay.
///
/// A `ws_h3` stream agrees datagrams once, on its CONNECT, before its relay
/// starts ([`Self::with_route`]). An `xhttp_h3` session is different: its relay
/// is spawned by whichever request creates the session, and that may be a POST
/// that came before the GET, so the anchor (GET or stream-one) attaches its
/// route to a relay that is already running — and a reconnected GET of the same
/// session replaces it. The relay therefore reads updates from here while it
/// runs: right before each stream packet it ingests (so an attach that happened
/// before that packet was sent is always in force) and from its select loop.
///
/// Only the latest update is kept: an attach that is superseded before the
/// relay saw it is dropped, which unregisters it.
///
/// The anchor also stamps the last uplink datagram ([`Self::last_uplink`]):
/// datagrams bypass the stream, so an owner that ages sessions by stream
/// activity (the xhttp registry janitor) reads this as client progress.
pub(in crate::server) struct DatagramAnchor {
    pending: Mutex<Option<AnchorUpdate>>,
    /// Lets the per-packet check skip the lock while nothing is pending.
    dirty: AtomicBool,
    changed: Notify,
    /// Downlink datagrams sent; shared with the relay's sender and WS writer.
    downlink: Arc<DatagramActivity>,
    /// When the last uplink datagram arrived, as nanos since `created` plus
    /// one (`0` = never).
    last_uplink_nanos: AtomicU64,
    created: Instant,
}

impl Default for DatagramAnchor {
    fn default() -> Self {
        Self {
            pending: Mutex::default(),
            dirty: AtomicBool::default(),
            changed: Notify::new(),
            downlink: Arc::default(),
            last_uplink_nanos: AtomicU64::new(0),
            created: Instant::now(),
        }
    }
}

impl DatagramAnchor {
    /// An anchor whose route is already agreed (`ws_h3`).
    pub(in crate::server) fn with_route(route: H3DatagramRoute) -> Arc<Self> {
        let anchor = Arc::new(Self::default());
        anchor.attach(route);
        anchor
    }

    pub(in crate::server) fn attach(&self, route: H3DatagramRoute) {
        self.publish(AnchorUpdate::Attach(route));
    }

    pub(in crate::server) fn detach(&self) {
        self.publish(AnchorUpdate::Detach);
    }

    fn publish(&self, update: AnchorUpdate) {
        // The superseded update (a route the relay never picked up) drops after
        // the lock, unregistering its stream.
        let superseded = self.pending.lock().replace(update);
        // Set after the lock is released: safe because an attach completes before
        // its `send_response`, so any packet the client sends after it sees the flag.
        self.dirty.store(true, Ordering::Release);
        self.changed.notify_one();
        drop(superseded);
    }

    /// The pending update, if any, without waiting.
    pub(in crate::server) fn take_update(&self) -> Option<AnchorUpdate> {
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return None;
        }
        self.pending.lock().take()
    }

    /// The downlink activity counter the relay's sender and writer share.
    pub(in crate::server) fn downlink_activity(&self) -> Arc<DatagramActivity> {
        Arc::clone(&self.downlink)
    }

    /// Stamps the arrival of one uplink datagram.
    pub(in crate::server) fn note_uplink(&self) {
        let nanos = u64::try_from(self.created.elapsed().as_nanos()).unwrap_or(u64::MAX - 1);
        self.last_uplink_nanos
            .store(nanos.saturating_add(1), Ordering::Relaxed);
    }

    /// When the last uplink datagram arrived; `None` before the first.
    pub(in crate::server) fn last_uplink(&self) -> Option<Instant> {
        match self.last_uplink_nanos.load(Ordering::Relaxed) {
            0 => None,
            nanos => Some(self.created + Duration::from_nanos(nanos - 1)),
        }
    }

    /// Waits for the next update. Cancel-safe: the update is taken in the same
    /// poll that returns it, and `notify_one` keeps a permit for a waiter that
    /// was not yet registered.
    pub(in crate::server) async fn next_update(&self) -> AnchorUpdate {
        loop {
            // Checks the slot itself, not `dirty`: a concurrent `take_update`
            // may have cleared the flag after this waiter's permit was issued.
            if let Some(update) = self.pending.lock().take() {
                return update;
            }
            self.changed.notified().await;
        }
    }
}

/// Outcome of [`DatagramDownlink::send`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::server) enum DownlinkSend {
    /// No anchor agreed datagrams (yet, or any more): the stream path, untouched
    /// and uncounted, as on a session that never offered them.
    NoTarget,
    /// Went out as one datagram.
    Sent,
    /// Did not fit, or failed to send: the stream carries it (counted).
    Fallback,
}

/// Sends a relay's downlink packets as HTTP/3 datagrams to its current anchor.
/// Shared by the SS-UDP response sender and the VLESS-UDP downlink pumps; each
/// hands it exactly the frame its stream would write as one Binary message.
pub(in crate::server) struct DatagramDownlink {
    pub(in crate::server) target: Arc<DatagramTarget>,
    pub(in crate::server) monitor: Option<Arc<ThroughputMonitor>>,
    pub(in crate::server) metrics: Arc<Metrics>,
    /// Shared with the stream's WS writer (see [`DatagramActivity`]).
    pub(in crate::server) activity: Arc<DatagramActivity>,
    /// Labels of the stream's own Binary-frame series, which datagrams feed too.
    pub(in crate::server) transport: Transport,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) app_protocol: AppProtocol,
    /// `proto` label of the datagram counters.
    pub(in crate::server) proto: &'static str,
}

impl DatagramDownlink {
    /// Whether an anchor currently takes datagrams.
    pub(in crate::server) fn is_live(&self) -> bool {
        self.target.load().is_some()
    }

    /// Sends `framed` as one datagram when it fits. `upstream_len` is the
    /// packet's size as read from upstream, for a caller whose stream path
    /// feeds the throttle monitor only once the packet reaches the stream
    /// sender (SS-UDP); `None` when the caller already fed it (VLESS-UDP).
    pub(in crate::server) fn send(
        &self,
        framed: &Bytes,
        upstream_len: Option<usize>,
    ) -> DownlinkSend {
        let target = self.target.load();
        let Some(peer) = target.as_deref() else {
            return DownlinkSend::NoTarget;
        };
        if self.try_send(peer, framed, upstream_len) {
            self.metrics.record_udp_h3_datagram("down", self.proto);
            DownlinkSend::Sent
        } else {
            self.metrics.record_udp_h3_datagram_fallback("down", self.proto);
            DownlinkSend::Fallback
        }
    }

    fn try_send(&self, peer: &DatagramPeer, framed: &Bytes, upstream_len: Option<usize>) -> bool {
        let fits = peer
            .connection
            .max_datagram_size()
            .is_some_and(|max| datagram_overhead(peer.quarter_stream_id) + framed.len() <= max);
        if !fits {
            return false;
        }
        // Backlog as the stream senders see it, measured on the datagram send
        // buffer instead of the data channel.
        let used =
            H3_DATAGRAM_BUFFER_BYTES.saturating_sub(peer.connection.datagram_send_buffer_space());
        // `send_datagram` may evict the oldest queued datagram to make room;
        // that is a UDP loss, not a failure of this one.
        if peer
            .connection
            .send_datagram(encode_datagram(peer.quarter_stream_id, framed))
            .is_err()
        {
            return false;
        }
        self.activity.note_send();
        // Same accounting the stream path does: the sender notes the upstream
        // bytes, the WS writer the bytes handed to the carrier. Here "handed to
        // the carrier" means handed to quinn: a datagram it later evicts from a
        // full send buffer is invisible to the monitor.
        if let Some(monitor) = &self.monitor {
            if let Some(len) = upstream_len {
                monitor.note_datagram(len, used, H3_DATAGRAM_BUFFER_BYTES);
            }
            monitor.add_outbound(framed.len() as u64);
        }
        self.metrics.record_websocket_binary_frame(
            self.transport,
            self.protocol,
            self.app_protocol,
            "down",
            framed.len(),
        );
        true
    }
}

/// Downlink sender of a datagram-capable SS-UDP stream. Wraps the stream's own
/// sender, which carries every packet that does not go out as a datagram — all
/// of them while the downlink has no target.
pub(in crate::server) struct DatagramResponseSender {
    pub(in crate::server) downlink: DatagramDownlink,
    pub(in crate::server) stream: UdpResponseSender,
    pub(in crate::server) padding: PaddingScheme,
}

impl ResponseSender for DatagramResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        if !self.downlink.is_live() {
            return Box::pin(self.stream.send_bytes(data));
        }
        // The same frame the stream sender would write as a Binary message (on
        // xhttp, before the stream's UDP record framing, which a datagram does
        // not need).
        let framed = carrier_padding::frame_downlink_message(self.padding, data.clone());
        match self.downlink.send(&framed, Some(data.len())) {
            DownlinkSend::Sent => Box::pin(async { true }),
            // The original packet: the stream sender pads it itself.
            DownlinkSend::NoTarget | DownlinkSend::Fallback => {
                Box::pin(self.stream.send_bytes(data))
            },
        }
    }

    fn protocol(&self) -> Protocol {
        self.stream.protocol()
    }

    fn app_protocol(&self) -> AppProtocol {
        self.stream.app_protocol()
    }
}

/// How a relay treats the routes its anchor hands it.
pub(in crate::server) enum LinkPolicy {
    /// SS-UDP: a route takes downlink datagrams at once. Sessions were counted
    /// when the anchor agreed them.
    Immediate,
    /// VLESS-UDP: a route takes downlink datagrams only after the client's first
    /// uplink datagram on it. The client sends datagrams only once it has read
    /// the response header, which rides the stream, so a datagram can never
    /// overtake that header. Each route is counted `negotiated` when applied:
    /// only now is the VLESS command known.
    AfterUplink,
    /// A VLESS session whose command is not plain UDP (TCP, mux / XUDP): every
    /// route is dropped (unregistered) and counted `declined`.
    Decline,
}

/// A relay's live datagram side: its anchor (where routes come from), the
/// downlink target its sender reads, and the uplink registration of the
/// current route. Dropping it unregisters the route and empties the target, so
/// a sender clone that outlives the relay lets go of the connection.
pub(in crate::server) struct DatagramLink {
    anchor: Arc<DatagramAnchor>,
    target: Arc<DatagramTarget>,
    registration: Option<DatagramRegistration>,
    /// The route's peer, held back until the first uplink datagram
    /// ([`LinkPolicy::AfterUplink`]).
    unarmed: Option<DatagramPeer>,
    agreed: bool,
    policy: LinkPolicy,
    metrics: Arc<Metrics>,
}

impl DatagramLink {
    /// Builds the link and applies a route agreed before it existed (every
    /// `ws_h3` stream, and an xhttp anchor that beat the relay).
    pub(in crate::server) fn new(
        anchor: Arc<DatagramAnchor>,
        target: Arc<DatagramTarget>,
        policy: LinkPolicy,
        metrics: Arc<Metrics>,
    ) -> Self {
        let mut link = Self {
            anchor,
            target,
            registration: None,
            unarmed: None,
            agreed: false,
            policy,
            metrics,
        };
        link.apply_pending();
        link
    }

    /// Whether a route is in force (uplink datagrams accepted).
    pub(in crate::server) fn agreed(&self) -> bool {
        self.agreed
    }

    /// Applies the anchor change published since the last check, if any. A
    /// relay calls it right before ingesting each stream packet, so an attach
    /// that happened before the client sent that packet is in force for it,
    /// whichever select arm won the race.
    pub(in crate::server) fn apply_pending(&mut self) {
        if let Some(update) = self.anchor.take_update() {
            self.apply(update);
        }
    }

    fn apply(&mut self, update: AnchorUpdate) {
        match update {
            AnchorUpdate::Attach(route) => {
                let H3DatagramRoute {
                    connection,
                    quarter_stream_id,
                    registration,
                } = route;
                let peer = DatagramPeer { connection, quarter_stream_id };
                match self.policy {
                    LinkPolicy::Decline => {
                        // `registration` drops at the end of this arm.
                        self.metrics.record_udp_h3_datagram_session("declined");
                        self.target.store(None);
                        self.registration = None;
                        self.agreed = false;
                        return;
                    },
                    LinkPolicy::Immediate => {
                        self.target.store(Some(Arc::new(peer)));
                        self.unarmed = None;
                    },
                    LinkPolicy::AfterUplink => {
                        self.metrics.record_udp_h3_datagram_session("negotiated");
                        self.target.store(None);
                        self.unarmed = Some(peer);
                    },
                }
                self.registration = Some(registration);
                self.agreed = true;
            },
            AnchorUpdate::Detach => {
                self.target.store(None);
                self.unarmed = None;
                self.registration = None;
                self.agreed = false;
            },
        }
    }

    /// Next uplink datagram of the current route, applying anchor changes on
    /// the way. Never resolves while no route delivers one. Cancel-safe: both
    /// waits are, and whatever they yield is handled before returning.
    pub(in crate::server) async fn next_datagram(&mut self) -> Bytes {
        loop {
            let event = tokio::select! {
                datagram = next_registered(&mut self.registration) => Ok(datagram),
                update = self.anchor.next_update() => Err(update),
            };
            match event {
                Ok(Some(datagram)) => {
                    self.anchor.note_uplink();
                    if let Some(peer) = self.unarmed.take() {
                        self.target.store(Some(Arc::new(peer)));
                    }
                    return datagram;
                },
                // The route stopped delivering (connection closed, or the id was
                // registered again). Not the end of the session: the stream
                // still carries it, and the next anchor may bring a new route.
                Ok(None) => self.registration = None,
                Err(update) => self.apply(update),
            }
        }
    }
}

impl Drop for DatagramLink {
    fn drop(&mut self) {
        self.registration = None;
        self.target.store(None);
    }
}

/// Next datagram of a registration; never resolves without one.
async fn next_registered(registration: &mut Option<DatagramRegistration>) -> Option<Bytes> {
    match registration {
        Some(registration) => registration.rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Next uplink datagram of an optional link; never resolves without one.
pub(in crate::server) async fn next_link_datagram(link: &mut Option<DatagramLink>) -> Bytes {
    match link {
        Some(link) => link.next_datagram().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
#[path = "tests/h3_datagram.rs"]
pub(in crate::server::transport) mod tests;
