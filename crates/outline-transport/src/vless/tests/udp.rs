use std::collections::VecDeque;
use std::net::Ipv4Addr;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;

use outline_wire::padding::PaddingScheme;

use super::*;
use crate::frame_io::{DatagramChannel, DatagramGate, PacketSource};

/// Channel that hands out a scripted sequence of packets, each tagged with its
/// source, then reports EOF. With `gate`, every receive first logs whether the
/// gate was open at that point.
#[derive(Default)]
struct ScriptedChannel {
    script: Mutex<VecDeque<(PacketSource, Bytes)>>,
    gate: Option<Arc<DatagramGate>>,
    gate_log: Mutex<Vec<bool>>,
}

impl ScriptedChannel {
    fn new(script: &[(PacketSource, &[u8])]) -> Arc<Self> {
        Arc::new(Self::scripted(script, None))
    }

    fn scripted(script: &[(PacketSource, &[u8])], gate: Option<Arc<DatagramGate>>) -> Self {
        Self {
            script: Mutex::new(
                script
                    .iter()
                    .map(|(source, bytes)| (*source, Bytes::copy_from_slice(bytes)))
                    .collect(),
            ),
            gate,
            gate_log: Mutex::default(),
        }
    }
}

#[async_trait]
impl DatagramChannel for ScriptedChannel {
    async fn send_datagram(&self, _data: Bytes) -> Result<()> {
        Ok(())
    }
    async fn recv_datagram(&self) -> Result<Option<Bytes>> {
        Ok(self.recv_datagram_with_source().await?.map(|(_, packet)| packet))
    }
    async fn recv_datagram_with_source(&self) -> Result<Option<(PacketSource, Bytes)>> {
        if let Some(gate) = &self.gate {
            self.gate_log.lock().push(gate.is_open());
        }
        Ok(self.script.lock().pop_front())
    }
    async fn close(&self) {}
}

fn transport(script: &[(PacketSource, &[u8])]) -> VlessUdpTransport {
    let target = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, 53);
    VlessUdpTransport::from_channel(ScriptedChannel::new(script), &[7; 16], &target, "test")
        .expect("transport builds")
}

const STREAM: PacketSource = PacketSource::Stream;
const DATAGRAM: PacketSource = PacketSource::Datagram;

/// A datagram that arrives while the stream holds the head of a split record
/// is its own record: it neither corrupts nor completes the stream's.
#[tokio::test]
async fn a_datagram_record_stays_out_of_the_stream_reassembly() {
    let transport = transport(&[
        // Response header, then the first two bytes of a five-byte record.
        (STREAM, &[VERSION_BYTE, 0, 0, 5, b'a', b'b']),
        (DATAGRAM, &[0, 3, b'x', b'y', b'z']),
        (STREAM, b"cde"),
    ]);
    assert_eq!(&transport.read_packet().await.unwrap()[..], b"xyz");
    assert_eq!(&transport.read_packet().await.unwrap()[..], b"abcde");
}

/// A datagram that is not exactly one record, or that comes before the
/// response header, is dropped and counted; the session carries on.
#[tokio::test]
async fn malformed_or_early_datagrams_are_dropped() {
    let transport = transport(&[
        (DATAGRAM, &[0, 1, b'e']),
        (STREAM, &[VERSION_BYTE, 0]),
        // Length says 4, body has 2.
        (DATAGRAM, &[0, 4, b'h', b'i']),
        // Two records in one datagram.
        (DATAGRAM, &[0, 1, b'a', 0, 1, b'b']),
        (DATAGRAM, &[0, 2, b'o', b'k']),
        (STREAM, &[0, 2, b'n', b'o']),
    ]);
    let early = dropped("early");
    let malformed = dropped("malformed");
    assert_eq!(&transport.read_packet().await.unwrap()[..], b"ok");
    assert_eq!(&transport.read_packet().await.unwrap()[..], b"no");
    assert!(transport.read_packet().await.is_err(), "EOF after the script");
    assert_counted(early, dropped("early"), 1.0);
    assert_counted(malformed, dropped("malformed"), 2.0);
}

const VERSION_BYTE: u8 = VLESS_VERSION;

const SCHEME: PaddingScheme = PaddingScheme::new(4, 16);

/// One padding frame around `real` (`real` empty: a cover frame).
fn padded(real: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    carrier_padding::frame_payload_into(SCHEME, real, &mut rand::rng(), &mut out);
    out
}

/// A transport on a padded path, as `from_channel` builds it when the carrier
/// padding is on.
fn padded_transport(channel: Arc<ScriptedChannel>) -> VlessUdpTransport {
    let target = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, 53);
    let mut transport =
        VlessUdpTransport::from_channel(channel, &[7; 16], &target, "test").expect("builds");
    transport.padding = CarrierPadding {
        scheme: SCHEME,
        ..CarrierPadding::disabled()
    };
    transport.recv_state.lock().padding_decoder = Some(PaddingDecoder::new());
    transport
}

/// Process-wide (other tests run alongside), so callers compare deltas.
fn dropped(reason: &str) -> f64 {
    let rendered = outline_metrics::render_prometheus(&[]).unwrap_or_default();
    let series = format!("outline_ws_udp_h3_datagram_dropped_total{{reason=\"{reason}\"}} ");
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(&series)?.parse().ok())
        .unwrap_or(0.0)
}

/// Counters are real only with the `metrics` feature (a no-op stub otherwise).
fn assert_counted(before: f64, after: f64, at_least: f64) {
    if cfg!(feature = "metrics") {
        assert!(after - before >= at_least, "counted {} < {at_least}", after - before);
    }
}

/// On a padded path a cover frame may arrive before the response header. It
/// must not open the datagram gate; the header does.
#[tokio::test]
async fn only_the_response_header_opens_the_datagram_gate() {
    let gate = Arc::new(DatagramGate::default());
    let cover = padded(&[]);
    let header = padded(&[VERSION_BYTE, 0]);
    let record = padded(&[0, 2, b'h', b'i']);
    let channel = Arc::new(ScriptedChannel::scripted(
        &[(STREAM, &cover), (STREAM, &header), (STREAM, &record)],
        Some(Arc::clone(&gate)),
    ));
    let mut transport = padded_transport(Arc::clone(&channel));
    transport.datagram_gate = Some(Arc::clone(&gate));

    assert_eq!(&transport.read_packet().await.unwrap()[..], b"hi");
    // Closed before the cover, still closed after it, open after the header.
    assert_eq!(*channel.gate_log.lock(), vec![false, false, true]);
    assert!(gate.is_open());
}

/// A padded datagram holding one record is accepted; a truncated padded one
/// (the frame cut short, so it decodes to nothing) is dropped and counted.
#[tokio::test]
async fn padded_datagram_records() {
    let good = padded(&[0, 3, b'a', b'b', b'c']);
    let truncated_frame = &padded(&[0, 3, b'x', b'y', b'z'])[..6];
    // A whole frame around a record whose length overruns it.
    let short_record = padded(&[0, 9, b'q']);
    let channel = Arc::new(ScriptedChannel::scripted(
        &[
            (STREAM, &padded(&[VERSION_BYTE, 0])),
            (DATAGRAM, truncated_frame),
            (DATAGRAM, &short_record),
            (DATAGRAM, &good),
        ],
        None,
    ));
    let transport = padded_transport(channel);
    let malformed = dropped("malformed");
    assert_eq!(&transport.read_packet().await.unwrap()[..], b"abc");
    assert_counted(malformed, dropped("malformed"), 2.0);
}
