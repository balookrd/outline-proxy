use super::{MAX_UDP_DATAGRAM, read_datagram, write_datagram};

/// Round-trips a datagram of `size` bytes and asserts byte-exact recovery.
async fn round_trip(size: usize) {
    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let mut wire: Vec<u8> = Vec::new();
    write_datagram(&mut wire, &payload).await.unwrap();

    let mut src: &[u8] = &wire;
    let mut buf = Vec::new();
    let len = read_datagram(&mut src, &mut buf).await.unwrap().unwrap();
    assert_eq!(len, size);
    assert_eq!(&buf[..len], &payload[..]);
    // The whole frame was consumed: prefix + payload, nothing left over.
    assert!(src.is_empty());
}

#[tokio::test]
async fn round_trips_across_sizes() {
    for size in [0usize, 1, 1500, 65535, 65536, MAX_UDP_DATAGRAM] {
        round_trip(size).await;
    }
}

#[tokio::test]
async fn preserves_boundaries_across_multiple_datagrams() {
    // Three back-to-back datagrams of distinct sizes must read back one at a
    // time on their exact boundaries — the SS-UDP atomicity guarantee.
    let sizes = [10usize, 0, 4096];
    let payloads: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(n, &s)| (0..s).map(|i| (i + n) as u8).collect())
        .collect();

    let mut wire: Vec<u8> = Vec::new();
    for p in &payloads {
        write_datagram(&mut wire, p).await.unwrap();
    }

    let mut src: &[u8] = &wire;
    let mut buf = Vec::new();
    for (n, &s) in sizes.iter().enumerate() {
        let len = read_datagram(&mut src, &mut buf).await.unwrap().unwrap();
        assert_eq!(len, s, "datagram {n} length");
        assert_eq!(&buf[..len], &payloads[n][..], "datagram {n} payload");
    }
    // Stream is now exhausted at a frame boundary.
    assert!(read_datagram(&mut src, &mut buf).await.unwrap().is_none());
}

#[tokio::test]
async fn clean_eof_at_boundary_returns_none() {
    let mut src: &[u8] = &[];
    let mut buf = Vec::new();
    assert!(read_datagram(&mut src, &mut buf).await.unwrap().is_none());
}

#[tokio::test]
async fn truncated_length_prefix_is_error() {
    // Two of the four length-prefix bytes, then EOF.
    let mut src: &[u8] = &[0x00, 0x00];
    let mut buf = Vec::new();
    let err = read_datagram(&mut src, &mut buf).await.unwrap_err();
    assert!(err.to_string().contains("truncated"), "{err}");
}

#[tokio::test]
async fn truncated_payload_is_error() {
    // Length says 10 bytes but only 5 follow.
    let mut wire = 10u32.to_be_bytes().to_vec();
    wire.extend_from_slice(&[1, 2, 3, 4, 5]);
    let mut src: &[u8] = &wire;
    let mut buf = Vec::new();
    assert!(read_datagram(&mut src, &mut buf).await.is_err());
}

#[tokio::test]
async fn oversized_length_prefix_is_rejected() {
    // A forged length past the cap must be rejected before any allocation.
    let forged = (MAX_UDP_DATAGRAM as u32) + 1;
    let wire = forged.to_be_bytes().to_vec();
    let mut src: &[u8] = &wire;
    let mut buf = Vec::new();
    let err = read_datagram(&mut src, &mut buf).await.unwrap_err();
    assert!(err.to_string().contains("exceeds max"), "{err}");
    // The buffer was left untouched — no giant allocation was attempted.
    assert!(buf.is_empty());
}

#[tokio::test]
async fn oversized_payload_is_rejected_on_write() {
    let payload = vec![0u8; MAX_UDP_DATAGRAM + 1];
    let mut wire: Vec<u8> = Vec::new();
    let err = write_datagram(&mut wire, &payload).await.unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
    assert!(wire.is_empty());
}
