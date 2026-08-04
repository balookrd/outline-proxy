//! `TransportStream::is_h3` must follow the XHTTP stream's real carrier:
//! `xhttp_h3` rides QUIC (true), `xhttp_h2`/`xhttp_h1` ride TCP (false).
//!
//! Regression for a spurious H3->H2 carrier downgrade: the WS-level
//! read-idle watchdog was armed on the `xhttp_h3` QUIC carrier because
//! `is_h3` only matched the native `ws_h3` variant. A quiet long-lived
//! session (e.g. an idle push socket) then tripped the 300s reaper and
//! capped the carrier to h2 even though H3 was healthy.

use crate::guards::AbortOnDrop;
use crate::ws_stream::TransportStream;
use crate::xhttp::{XhttpStream, XhttpSubmode, inbound_channel, outbound_channel};

fn dummy_xhttp_stream(carrier_is_h3: bool) -> XhttpStream {
    let (_in_tx, in_rx) = inbound_channel();
    let (out_tx, _out_rx) = outbound_channel();
    let driver = AbortOnDrop::new(tokio::spawn(async {
        std::future::pending::<()>().await;
    }));
    XhttpStream::from_channels(
        in_rx,
        out_tx,
        driver,
        XhttpSubmode::PacketUp,
        carrier_is_h3,
        false,
        None,
        None,
    )
}

#[tokio::test]
async fn xhttp_h3_carrier_reports_is_h3() {
    let stream = dummy_xhttp_stream(true);
    assert!(stream.carrier_is_h3());
    let transport = TransportStream::new_xhttp(stream, None);
    assert!(transport.is_h3(), "xhttp_h3 must be treated as a QUIC carrier");
}

#[tokio::test]
async fn xhttp_h2_carrier_is_not_h3() {
    let stream = dummy_xhttp_stream(false);
    assert!(!stream.carrier_is_h3());
    let transport = TransportStream::new_xhttp(stream, None);
    assert!(!transport.is_h3(), "xhttp_h2/h1 ride TCP and keep the read-idle watchdog");
}

/// `CarrierLossProbe::Quic` and the `CarrierLossCounters` trait it observes
/// through only exist behind the `h3` feature (see `carrier_loss.rs`) — the
/// ownership pin below constructs that variant directly, so it needs the
/// same gate. `cargo check -p outline-transport --all-targets` without `h3`
/// used to fail here: this module compiled unconditionally
/// (`xhttp/mod.rs`), and the workspace gate only passed because
/// `outline-ws-rust` unifies the `h3` feature back in for every other crate
/// in the graph.
#[cfg(feature = "h3")]
mod quic_ownership {
    use std::sync::{Arc, Weak};

    use crate::guards::AbortOnDrop;
    use crate::xhttp::{XhttpStream, XhttpSubmode, inbound_channel, outbound_channel};
    use crate::{CarrierLossCounters, CarrierLossProbe, CarrierLossSample};

    /// A minimal, real `CarrierLossCounters` implementer — only the counters
    /// it reports are stubbed, not the `Arc`/`Weak`/drop machinery the
    /// assertion below actually exercises.
    struct StubCarrier;

    impl CarrierLossCounters for StubCarrier {
        fn loss_counters(&self) -> Option<CarrierLossSample> {
            Some(CarrierLossSample { sent: 1, lost: 0, alive: true })
        }
    }

    /// Pins the 1:1 ownership pairing the whole fix rests on: `XhttpStream` is
    /// handed both a probe (`Weak`) and the strong `Arc` behind it — exactly as
    /// `xhttp/h3.rs::h3_handshake` constructs them — and a second, independent
    /// clone of the probe (standing in for the copy `outline-uplink`'s registry
    /// holds) must start reporting the carrier dead the moment the stream drops,
    /// with no help from the registry's own staleness eviction. If a future
    /// change went back to handing the registry a strong reference — or
    /// `XhttpStream` stopped owning `_quic_carrier` — this test would catch it
    /// where the pure `Weak`/`Arc` tests in `carrier_loss.rs` cannot, because
    /// those never touch `XhttpStream`'s ownership wiring at all.
    #[tokio::test]
    async fn dropping_the_xhttp_stream_drops_its_owned_quic_carrier() {
        let carrier: Arc<dyn CarrierLossCounters> = Arc::new(StubCarrier);
        let counters: Weak<dyn CarrierLossCounters> = Arc::downgrade(&carrier);
        let probe = CarrierLossProbe::Quic { counters, identity: 42 };
        // Stands in for the clone `TransportStream::loss_probe()` would hand the
        // uplink's `CarrierLossRegistry` — held independently of the stream, the
        // same way the registry holds it independently of the transport.
        let registry_probe = probe.try_clone().expect("the Quic variant clones");

        let (_in_tx, in_rx) = inbound_channel();
        let (out_tx, _out_rx) = outbound_channel();
        let driver = AbortOnDrop::new(tokio::spawn(async {
            std::future::pending::<()>().await;
        }));
        let stream = XhttpStream::from_channels(
            in_rx,
            out_tx,
            driver,
            XhttpSubmode::PacketUp,
            true,
            false,
            Some(probe),
            Some(carrier),
        );

        assert!(
            registry_probe.sample().expect("carrier alive").alive,
            "the carrier must read alive while the stream that owns it is alive"
        );

        drop(stream);

        let sample = registry_probe.sample().expect("a dead carrier is still `Some`");
        assert!(
            !sample.alive,
            "dropping the XhttpStream must drop its owned quic carrier, so an \
             independently-held probe (standing in for the registry's copy) \
             reports the carrier dead with no eviction help"
        );
    }
}
