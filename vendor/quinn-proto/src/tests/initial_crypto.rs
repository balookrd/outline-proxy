//! Browser-like ClientHello layouts (outline-proxy patch): the handshake completes,
//! with and without a Retry, client Initials stay at 1200 bytes, and the Chaos layout
//! scatters the hello over extra CRYPTO frames and PINGs.

use std::sync::Arc;

use super::util::*;
use crate::{ClientConfig, ConnectionStats, InitialCryptoLayout, TransportConfig};

const LAYOUTS: [InitialCryptoLayout; 3] =
    [InitialCryptoLayout::Contiguous, InitialCryptoLayout::Chaos, InitialCryptoLayout::SniSlice];

fn config(layout: InitialCryptoLayout) -> ClientConfig {
    let mut cfg = client_config();
    let mut transport = TransportConfig::default();
    transport.initial_crypto_layout(layout);
    cfg.transport = Arc::new(transport);
    cfg
}

/// Datagram sizes of the client's first flight and the client's stats after it.
fn first_flight(layout: InitialCryptoLayout) -> (Vec<usize>, ConnectionStats) {
    let mut pair = Pair::default();
    let ch = pair.begin_connect(config(layout));
    pair.client.drive(pair.time, pair.server.addr);
    let sizes = pair
        .client
        .outbound
        .iter()
        .flat_map(|(t, b)| match t.segment_size {
            Some(s) => b.chunks(s).map(<[u8]>::len).collect::<Vec<_>>(),
            None => vec![t.size],
        })
        .collect();
    (sizes, pair.client_conn_mut(ch).stats())
}

#[test]
fn every_layout_completes_the_handshake() {
    let _guard = subscribe();
    for layout in LAYOUTS {
        let mut pair = Pair::default();
        pair.connect_with(config(layout));
    }
}

#[test]
fn every_layout_completes_the_handshake_after_a_retry() {
    let _guard = subscribe();
    for layout in LAYOUTS {
        let mut pair = Pair::default();
        pair.server.handle_incoming = Box::new(validate_incoming);
        pair.connect_with(config(layout));
    }
}

/// After a Retry the hello is laid out afresh: the re-sent first Initial carries the
/// profile's CRYPTO frames again, not the upstream single frame.
#[test]
fn retry_lays_the_hello_out_again() {
    let _guard = subscribe();
    let crypto_frames = |layout, retry: bool| {
        let mut pair = Pair::default();
        if retry {
            pair.server.handle_incoming = Box::new(validate_incoming);
        }
        let ch = pair.begin_connect(config(layout));
        pair.drive();
        pair.client_conn_mut(ch).stats().frame_tx.crypto
    };
    for (layout, resent) in [
        (InitialCryptoLayout::Contiguous, 1),
        (InitialCryptoLayout::SniSlice, 2),
    ] {
        let extra = crypto_frames(layout, true) - crypto_frames(layout, false);
        assert_eq!(extra, resent, "{layout:?}");
    }
}

#[test]
fn client_initials_keep_their_size() {
    let _guard = subscribe();
    for layout in LAYOUTS {
        let (sizes, stats) = first_flight(layout);
        // The test hello fits one Initial (no ML-KEM share); two-packet plans are
        // covered by the planner's own tests.
        assert_eq!(sizes, vec![1200], "{layout:?}");
        let frames = stats.frame_tx.crypto;
        match layout {
            InitialCryptoLayout::Contiguous => assert_eq!(frames, 1),
            // The part after the SNI middle, then the head.
            InitialCryptoLayout::SniSlice => assert_eq!(frames, 2),
            InitialCryptoLayout::Chaos => assert!(frames >= 2, "{frames}"),
        }
    }
}

#[test]
fn chaos_adds_crypto_frames_and_pings() {
    let _guard = subscribe();
    let (mut most_frames, mut most_pings) = (0, 0);
    for _ in 0..50 {
        let (_, stats) = first_flight(InitialCryptoLayout::Chaos);
        most_frames = most_frames.max(stats.frame_tx.crypto);
        most_pings = most_pings.max(stats.frame_tx.ping);
    }
    assert!(most_frames >= 8, "{most_frames}");
    assert!(most_pings >= 8, "{most_pings}");
}
