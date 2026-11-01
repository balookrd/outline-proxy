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
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use super::decode_datagram;

    pub const DATAGRAM_QUEUE: usize = 256;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DropReason {
        UnknownStream,
        Malformed,
        /// The registration's bounded receive queue was full.
        QueueFull,
    }

    #[derive(Default)]
    struct Routes {
        map: HashMap<u64, (u64, mpsc::Sender<Bytes>)>,
        next_generation: u64,
        /// Set once the connection stops yielding datagrams.
        closed: bool,
    }

    /// One reader of `read_datagram` per QUIC connection, routing each HTTP/3
    /// datagram to the request stream it is bound to. Dropping the demux stops
    /// the reader and releases its connection handle.
    pub struct DatagramDemux {
        routes: Arc<Mutex<Routes>>,
        reader: JoinHandle<()>,
    }

    impl Drop for DatagramDemux {
        fn drop(&mut self) {
            self.reader.abort();
        }
    }

    /// Receiving half for one request stream; unregisters on drop. When the
    /// connection closes, `rx.recv()` returns `None`.
    pub struct DatagramRegistration {
        pub rx: mpsc::Receiver<Bytes>,
        id: u64,
        generation: u64,
        demux: Arc<DatagramDemux>,
    }

    impl Drop for DatagramRegistration {
        fn drop(&mut self) {
            let mut routes = self.demux.routes.lock().expect("demux lock");
            // A newer registration of the same id must keep its route.
            if routes.map.get(&self.id).is_some_and(|(g, _)| *g == self.generation) {
                routes.map.remove(&self.id);
            }
        }
    }

    impl DatagramDemux {
        pub fn spawn(
            connection: quinn::Connection,
            on_drop: Arc<dyn Fn(DropReason) + Send + Sync>,
        ) -> Arc<Self> {
            let routes = Arc::new(Mutex::new(Routes::default()));
            let task_routes = Arc::clone(&routes);
            let reader = tokio::spawn(async move {
                while let Ok(datagram) = connection.read_datagram().await {
                    let Some((id, payload)) = decode_datagram(datagram) else {
                        on_drop(DropReason::Malformed);
                        continue;
                    };
                    let tx = task_routes
                        .lock()
                        .expect("demux lock")
                        .map
                        .get(&id)
                        .map(|(_, tx)| tx.clone());
                    match tx {
                        // A full queue drops like a lost UDP packet, but is counted;
                        // a closed one (registration dropped) is silently ignored.
                        Some(tx) => {
                            if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(payload) {
                                on_drop(DropReason::QueueFull);
                            }
                        },
                        None => on_drop(DropReason::UnknownStream),
                    }
                }
                // Connection closed: dropping the senders ends every `rx`.
                let mut routes = task_routes.lock().expect("demux lock");
                routes.map.clear();
                routes.closed = true;
            });
            Arc::new(Self { routes, reader })
        }

        /// Replaces any earlier registration of the same id (its `rx` then ends).
        pub fn register(self: &Arc<Self>, quarter_stream_id: u64) -> DatagramRegistration {
            let (tx, rx) = mpsc::channel(DATAGRAM_QUEUE);
            let mut routes = self.routes.lock().expect("demux lock");
            let generation = routes.next_generation;
            routes.next_generation += 1;
            if !routes.closed {
                routes.map.insert(quarter_stream_id, (generation, tx));
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
#[cfg(feature = "h3-datagram")]
pub use demux::{DATAGRAM_QUEUE, DatagramDemux, DatagramRegistration, DropReason};

#[cfg(test)]
#[path = "tests/h3_datagram.rs"]
mod tests;
