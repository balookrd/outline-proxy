//! HTTP/3 datagrams (RFC 9297) bound to a request stream: a QUIC DATAGRAM
//! payload is `varint(quarter_stream_id) || payload`, `quarter_stream_id =
//! stream_id >> 2`. The carriers put in `payload` exactly the bytes they would
//! otherwise send as one WebSocket Binary frame or one xhttp UDP record.

use bytes::{BufMut, Bytes, BytesMut};

/// Bytes the quarter-stream-id prefix takes (RFC 9000 §16 varint).
pub fn datagram_overhead(quarter_stream_id: u64) -> usize {
    match quarter_stream_id {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

pub fn encode_datagram(quarter_stream_id: u64, payload: &[u8]) -> Bytes {
    debug_assert!(quarter_stream_id < 1 << 62, "varint range");
    let len = datagram_overhead(quarter_stream_id);
    let mut out = BytesMut::with_capacity(len + payload.len());
    match len {
        1 => out.put_u8(quarter_stream_id as u8),
        2 => out.put_u16(0x4000 | quarter_stream_id as u16),
        4 => out.put_u32(0x8000_0000 | quarter_stream_id as u32),
        _ => out.put_u64(0xc000_0000_0000_0000 | quarter_stream_id),
    }
    out.put_slice(payload);
    out.freeze()
}

/// `None` on an empty or truncated prefix.
pub fn decode_datagram(mut datagram: Bytes) -> Option<(u64, Bytes)> {
    let first = *datagram.first()?;
    let len = 1usize << (first >> 6);
    if datagram.len() < len {
        return None;
    }
    let mut id = u64::from(first & 0x3f);
    for b in &datagram[1..len] {
        id = (id << 8) | u64::from(*b);
    }
    let payload = datagram.split_off(len);
    Some((id, payload))
}

#[cfg(feature = "h3-datagram")]
mod demux {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use super::decode_datagram;

    /// Bytes one registration may hold unread.
    pub const REGISTRATION_QUEUE_BYTES: usize = 512 * 1024;
    /// Bytes all registrations of one connection may hold unread.
    pub const CONNECTION_QUEUE_BYTES: usize = 4 * 1024 * 1024;
    /// Unread datagrams one registration may hold, whatever their size.
    pub const DATAGRAM_QUEUE: usize = 1024;
    /// A consumer that has not read for this long when its queue overflows
    /// is stalled ([`DropReason::QueueStalled`]), not hit by a burst.
    pub const QUEUE_STALL: Duration = Duration::from_millis(50);

    /// How long an unregistered stream's id keeps absorbing datagrams as
    /// [`DropReason::ClosedStream`]: the peer learns of the close about an RTT
    /// later and its queued datagrams drain after that.
    pub const TOMBSTONE_TTL: Duration = Duration::from_secs(10);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DropReason {
        UnknownStream,
        /// For a stream that unregistered within [`TOMBSTONE_TTL`]: the expected
        /// tail of a closed session.
        ClosedStream,
        Malformed,
        /// The registration's queue overflowed while its consumer was reading.
        QueueFull,
        /// The registration's queue overflowed and its consumer had not read for
        /// [`QUEUE_STALL`].
        QueueStalled,
    }

    /// Accounting one registration shares with the reader.
    struct Queue {
        bytes: AtomicUsize,
        datagrams: AtomicUsize,
        /// Start of the consumer's current idle stretch, as nanos since
        /// `epoch`: the later of its last read and the moment its queue last
        /// turned non-empty. Waiting on an empty queue is not stalling.
        idle_since_nanos: AtomicU64,
        /// Bytes queued and unread over all registrations of the connection.
        connection: Arc<AtomicUsize>,
        epoch: Instant,
    }

    impl Queue {
        fn now(&self) -> u64 {
            u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
        }

        fn mark_active(&self) {
            self.idle_since_nanos.store(self.now(), Ordering::Relaxed);
        }
    }

    /// One queued datagram. Its bytes are added to the registration's and the
    /// connection's counts when it is made and returned when it drops, so
    /// every datagram is released exactly once: read, rejected by
    /// `try_send`, or discarded with the channel (a registration dropped
    /// while the reader was mid-send, a replaced generation, a closed
    /// connection).
    struct Queued {
        payload: Bytes,
        len: usize,
        queue: Arc<Queue>,
    }

    impl Queued {
        fn new(payload: Bytes, queue: Arc<Queue>) -> Self {
            let len = payload.len();
            queue.bytes.fetch_add(len, Ordering::AcqRel);
            queue.connection.fetch_add(len, Ordering::AcqRel);
            if queue.datagrams.fetch_add(1, Ordering::AcqRel) == 0 {
                // The queue turns non-empty: the idle clock starts now.
                queue.mark_active();
            }
            Self { payload, len, queue }
        }
    }

    impl Drop for Queued {
        fn drop(&mut self) {
            self.queue.bytes.fetch_sub(self.len, Ordering::AcqRel);
            self.queue.connection.fetch_sub(self.len, Ordering::AcqRel);
            self.queue.datagrams.fetch_sub(1, Ordering::AcqRel);
        }
    }

    #[derive(Clone, Copy)]
    struct Limits {
        registration_bytes: usize,
        connection_bytes: usize,
        queue_stall: Duration,
    }

    const LIMITS: Limits = Limits {
        registration_bytes: REGISTRATION_QUEUE_BYTES,
        connection_bytes: CONNECTION_QUEUE_BYTES,
        queue_stall: QUEUE_STALL,
    };

    /// An overflow is a stall when the consumer has neither read nor seen its
    /// queue turn non-empty for `stall`. An empty queue is never stalled: its
    /// overflow comes from the connection budget its neighbours filled.
    fn overflow_reason(queue: &Queue, stall: Duration) -> DropReason {
        if queue.datagrams.load(Ordering::Acquire) == 0 {
            return DropReason::QueueFull;
        }
        let idle = queue
            .now()
            .saturating_sub(queue.idle_since_nanos.load(Ordering::Relaxed));
        if Duration::from_nanos(idle) >= stall {
            DropReason::QueueStalled
        } else {
            DropReason::QueueFull
        }
    }

    /// A QUIC connection's path MTU state; counts are deltas since the previous
    /// sample of the same connection. `current_mtu` is `None` on the sample
    /// taken at close: a short-lived connection (a probe) closes before
    /// DPLPMTUD lifts the MTU off 1200, and observing it would flood the
    /// histogram with the starting value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PathSample {
        pub current_mtu: Option<u16>,
        pub black_holes: u64,
        pub lost_probes: u64,
    }

    pub type OnPathSample = Arc<dyn Fn(PathSample) + Send + Sync>;

    pub const PATH_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

    /// Turns cumulative counters into a sample of deltas against `base`, then
    /// advances `base`. The MTU is carried only on periodic samples.
    pub(crate) fn next_sample(
        base: &mut (u64, u64),
        current_mtu: u16,
        black_holes: u64,
        lost_probes: u64,
        closed: bool,
    ) -> PathSample {
        let sample = PathSample {
            current_mtu: (!closed).then_some(current_mtu),
            black_holes: black_holes.saturating_sub(base.0),
            lost_probes: lost_probes.saturating_sub(base.1),
        };
        *base = (black_holes, lost_probes);
        sample
    }

    /// Samples `connection`'s path every `every`; at close it reports the
    /// remaining counter deltas only (no MTU).
    async fn watch_path(connection: quinn::Connection, every: Duration, on_path: OnPathSample) {
        let mut base = (0, 0);
        loop {
            let closed = tokio::select! {
                _ = connection.closed() => true,
                () = tokio::time::sleep(every) => false,
            };
            let path = connection.stats().path;
            on_path(next_sample(
                &mut base,
                path.current_mtu,
                path.black_holes_detected,
                path.lost_plpmtud_probes,
                closed,
            ));
            if closed {
                return;
            }
        }
    }

    enum Route {
        Live {
            generation: u64,
            tx: mpsc::Sender<Queued>,
            queue: Arc<Queue>,
        },
        /// Unregistered at this instant; absorbs the stream's tail until
        /// `tombstone_ttl` passes.
        Closed(Instant),
    }

    struct Routes {
        map: HashMap<u64, Route>,
        next_generation: u64,
        /// Set once the connection stops yielding datagrams.
        closed: bool,
        tombstone_ttl: Duration,
    }

    impl Routes {
        fn new(tombstone_ttl: Duration) -> Self {
            Self {
                map: HashMap::new(),
                next_generation: 0,
                closed: false,
                tombstone_ttl,
            }
        }

        /// Drops tombstones older than the TTL.
        fn prune(&mut self, now: Instant) {
            let ttl = self.tombstone_ttl;
            self.map.retain(
                |_, route| !matches!(route, Route::Closed(at) if now.duration_since(*at) >= ttl),
            );
        }
    }

    enum Lookup {
        Live(mpsc::Sender<Queued>, Arc<Queue>),
        Closed,
        Unknown,
    }

    /// One reader of `read_datagram` per QUIC connection, routing each HTTP/3
    /// datagram to the request stream it is bound to. Dropping the demux stops
    /// the reader and releases its connection handle.
    pub struct DatagramDemux {
        routes: Arc<Mutex<Routes>>,
        reader: JoinHandle<()>,
        path_watch: Option<JoinHandle<()>>,
        /// Bytes queued and unread over all registrations.
        queued: Arc<AtomicUsize>,
        /// Origin of the registrations' idle clocks.
        epoch: Instant,
    }

    impl Drop for DatagramDemux {
        fn drop(&mut self) {
            self.reader.abort();
            if let Some(watch) = &self.path_watch {
                watch.abort();
            }
        }
    }

    /// Receiving half for one request stream; unregisters on drop. When the
    /// connection closes, [`Self::recv`] returns `None`.
    pub struct DatagramRegistration {
        rx: mpsc::Receiver<Queued>,
        id: u64,
        generation: u64,
        demux: Arc<DatagramDemux>,
    }

    impl DatagramRegistration {
        /// Next datagram; `None` once the connection closed or the id was
        /// registered again. Cancel-safe: the datagram is taken and accounted
        /// in the same poll.
        pub async fn recv(&mut self) -> Option<Bytes> {
            let queued = self.rx.recv().await?;
            Some(Self::take(queued))
        }

        /// A queued datagram, if any, without waiting.
        pub fn try_recv(&mut self) -> Option<Bytes> {
            let queued = self.rx.try_recv().ok()?;
            Some(Self::take(queued))
        }

        /// Marks the read, then drops `queued`, which returns its bytes.
        fn take(mut queued: Queued) -> Bytes {
            queued.queue.mark_active();
            std::mem::take(&mut queued.payload)
        }
    }

    impl Drop for DatagramRegistration {
        fn drop(&mut self) {
            // The tombstone goes in before `rx` closes (it drops after this
            // body), so datagrams arriving meanwhile count as `closed_stream`.
            // Queued datagrams, and any the reader writes into the channel
            // after this, return their bytes when the channel drops them.
            let mut routes = self.demux.routes.lock().expect("demux lock");
            // A newer registration of the same id must keep its route.
            let current = matches!(
                routes.map.get(&self.id),
                Some(Route::Live { generation, .. }) if *generation == self.generation
            );
            if current {
                // Pruning on every unregister bounds the tombstones to the
                // closes of the last TTL.
                let now = Instant::now();
                routes.prune(now);
                routes.map.insert(self.id, Route::Closed(now));
            }
        }
    }

    impl DatagramDemux {
        pub fn spawn(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
        ) -> Arc<Self> {
            Self::spawn_inner(connection, on_drop, None, TOMBSTONE_TTL, LIMITS)
        }

        /// As [`Self::spawn`], also reporting the connection's path to `on_path`
        /// every [`PATH_SAMPLE_INTERVAL`].
        pub fn spawn_watched(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
            on_path: OnPathSample,
        ) -> Arc<Self> {
            Self::spawn_inner(
                connection,
                on_drop,
                Some((on_path, PATH_SAMPLE_INTERVAL)),
                TOMBSTONE_TTL,
                LIMITS,
            )
        }

        #[cfg(test)]
        pub(crate) fn spawn_watched_every(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
            on_path: OnPathSample,
            every: Duration,
        ) -> Arc<Self> {
            Self::spawn_inner(connection, on_drop, Some((on_path, every)), TOMBSTONE_TTL, LIMITS)
        }

        #[cfg(test)]
        pub(crate) fn spawn_with_ttl(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
            tombstone_ttl: Duration,
        ) -> Arc<Self> {
            Self::spawn_inner(connection, on_drop, None, tombstone_ttl, LIMITS)
        }

        #[cfg(test)]
        pub(crate) fn spawn_with_limits(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
            registration_bytes: usize,
            connection_bytes: usize,
            queue_stall: Duration,
        ) -> Arc<Self> {
            let limits = Limits {
                registration_bytes,
                connection_bytes,
                queue_stall,
            };
            Self::spawn_inner(connection, on_drop, None, TOMBSTONE_TTL, limits)
        }

        fn spawn_inner(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
            path: Option<(OnPathSample, Duration)>,
            tombstone_ttl: Duration,
            limits: Limits,
        ) -> Arc<Self> {
            let path_watch = path.map(|(on_path, every)| {
                tokio::spawn(watch_path(connection.clone(), every, on_path))
            });
            let routes = Arc::new(Mutex::new(Routes::new(tombstone_ttl)));
            let task_routes = Arc::clone(&routes);
            let queued = Arc::new(AtomicUsize::new(0));
            let task_queued = Arc::clone(&queued);
            let epoch = Instant::now();
            let reader = tokio::spawn(async move {
                while let Ok(datagram) = connection.read_datagram().await {
                    let Some((id, payload)) = decode_datagram(datagram) else {
                        on_drop(DropReason::Malformed);
                        continue;
                    };
                    let lookup = {
                        let mut routes = task_routes.lock().expect("demux lock");
                        let ttl = routes.tombstone_ttl;
                        match routes.map.get(&id) {
                            Some(Route::Live { tx, queue, .. }) => {
                                Lookup::Live(tx.clone(), Arc::clone(queue))
                            },
                            Some(Route::Closed(at)) if at.elapsed() < ttl => Lookup::Closed,
                            Some(Route::Closed(_)) => {
                                routes.map.remove(&id);
                                Lookup::Unknown
                            },
                            None => Lookup::Unknown,
                        }
                    };
                    match lookup {
                        // An overflowing queue drops like a lost UDP packet, but is
                        // counted; a closed one (receiver gone) is silently ignored.
                        // The reader is the only one adding to a queue's counters,
                        // so the budget check and the add in `Queued::new` do not
                        // race with themselves; a concurrent release only lowers
                        // the counts.
                        Lookup::Live(tx, queue) => {
                            let len = payload.len();
                            if queue.bytes.load(Ordering::Acquire) + len > limits.registration_bytes
                            {
                                on_drop(overflow_reason(&queue, limits.queue_stall));
                                continue;
                            }
                            if task_queued.load(Ordering::Acquire) + len > limits.connection_bytes {
                                // Other registrations may hold the connection's
                                // budget, but the drop is reported for the arriving
                                // one, as queue_full or queue_stalled by its own
                                // clock: the label set has no connection-wide reason.
                                on_drop(overflow_reason(&queue, limits.queue_stall));
                                continue;
                            }
                            // On `Err` the returned `Queued` drops here and
                            // gives its bytes back.
                            let queued = Queued::new(payload, Arc::clone(&queue));
                            if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(queued) {
                                on_drop(overflow_reason(&queue, limits.queue_stall));
                            }
                        },
                        Lookup::Closed => on_drop(DropReason::ClosedStream),
                        Lookup::Unknown => on_drop(DropReason::UnknownStream),
                    }
                }
                // Connection closed: dropping the senders ends every `rx`.
                let mut routes = task_routes.lock().expect("demux lock");
                routes.map.clear();
                routes.closed = true;
            });
            Arc::new(Self {
                routes,
                reader,
                path_watch,
                queued,
                epoch,
            })
        }

        /// Bytes queued and not yet read, over all registrations.
        pub fn queued_bytes(&self) -> usize {
            self.queued.load(Ordering::Acquire)
        }

        /// Replaces any earlier registration of the same id (its `rx` then ends).
        pub fn register(self: &Arc<Self>, quarter_stream_id: u64) -> DatagramRegistration {
            let (tx, rx) = mpsc::channel(DATAGRAM_QUEUE);
            let queue = Arc::new(Queue {
                bytes: AtomicUsize::new(0),
                datagrams: AtomicUsize::new(0),
                idle_since_nanos: AtomicU64::new(0),
                connection: Arc::clone(&self.queued),
                epoch: self.epoch,
            });
            // A fresh registration counts as just read: it is not stalled.
            queue.mark_active();
            let mut routes = self.routes.lock().expect("demux lock");
            let generation = routes.next_generation;
            routes.next_generation += 1;
            if !routes.closed {
                // Replaces a tombstone of the same id, if any.
                routes.map.insert(
                    quarter_stream_id,
                    Route::Live {
                        generation,
                        tx,
                        queue: Arc::clone(&queue),
                    },
                );
            }
            drop(routes);
            DatagramRegistration {
                rx,
                id: quarter_stream_id,
                generation,
                demux: Arc::clone(self),
            }
        }
    }
}
#[cfg(all(test, feature = "h3-datagram"))]
use demux::next_sample;
#[cfg(feature = "h3-datagram")]
pub use demux::{
    CONNECTION_QUEUE_BYTES, DATAGRAM_QUEUE, DatagramDemux, DatagramRegistration, DropReason,
    OnPathSample, PATH_SAMPLE_INTERVAL, PathSample, QUEUE_STALL, REGISTRATION_QUEUE_BYTES,
    TOMBSTONE_TTL,
};

#[cfg(test)]
#[path = "tests/h3_datagram.rs"]
mod tests;
