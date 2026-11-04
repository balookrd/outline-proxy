use std::ops::Range;

use rand::{SeedableRng, rngs::StdRng};

use super::*;

/// A ClientHello with an empty session id, three cipher suites, one compression method
/// and `extensions` (type, body), in this order.
fn hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend([7u8; 32]);
    body.push(0);
    body.extend([0, 6, 0x13, 1, 0x13, 2, 0x13, 3]);
    body.extend([1, 0]);
    let mut ext = Vec::new();
    for (ty, data) in extensions {
        ext.extend(ty.to_be_bytes());
        ext.extend((data.len() as u16).to_be_bytes());
        ext.extend(data);
    }
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut out = vec![1];
    out.extend(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend(body);
    out
}

fn sni(host: &[u8]) -> (u16, Vec<u8>) {
    let mut body = ((host.len() + 3) as u16).to_be_bytes().to_vec();
    body.push(0);
    body.extend((host.len() as u16).to_be_bytes());
    body.extend(host);
    (0, body)
}

/// Every byte of `0..len` is covered exactly once.
fn assert_partition(packets: &[Vec<Range<usize>>], len: usize) {
    let mut all: Vec<Range<usize>> = packets.iter().flatten().cloned().collect();
    all.sort_by_key(|r| r.start);
    let mut next = 0;
    for r in all {
        assert_eq!(r.start, next, "gap or overlap at {next}");
        assert!(!r.is_empty());
        next = r.end;
    }
    assert_eq!(next, len);
}

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

#[test]
fn finds_the_sni_host_name() {
    let h = hello(&[(45, vec![1, 1]), sni(b"localtest.me"), (43, vec![2, 3, 4])]);
    let r = sni_range(&h).unwrap();
    assert_eq!(&h[r], b"localtest.me");
    assert!(is_client_hello(&h));
}

#[test]
fn no_sni_and_truncated_hellos_are_not_parsed() {
    let h = hello(&[(45, vec![1, 1])]);
    assert_eq!(sni_range(&h), None);
    let full = hello(&[sni(b"example.com")]);
    assert_eq!(sni_range(&full[..full.len() - 3]), None);
    assert!(!is_client_hello(&full[..full.len() - 3]));
    assert!(!is_client_hello(&[2, 0, 0, 0]));
}

// Firefox, measured: 1894-byte hello, SNI host at 124..136, first Initial carries
// [1077, 1894) then [0, 130), the second [130, 1077).
#[test]
fn sni_slice_matches_the_firefox_capture() {
    let packets =
        plan(InitialCryptoLayout::SniSlice, 1894, Some(124..136), 1150, &mut rng(1)).unwrap();
    assert_eq!(packets, vec![vec![1077..1894, 0..130], vec![130..1077]]);
}

// SNI past the middle (Firefox shuffles its extensions): all of the part after the
// cut, then the end of the head; the next packet starts at offset 0.
#[test]
fn sni_slice_with_a_late_sni_sends_the_end_of_the_head() {
    let packets =
        plan(InitialCryptoLayout::SniSlice, 1894, Some(1300..1312), 1150, &mut rng(1)).unwrap();
    assert_eq!(packets, vec![vec![1306..1894, 947..1306], vec![0..947]]);
}

#[test]
fn sni_slice_without_an_sni_does_not_apply() {
    assert_eq!(plan(InitialCryptoLayout::SniSlice, 1894, None, 1150, &mut rng(1)), None);
}

#[test]
fn contiguous_never_plans() {
    assert_eq!(
        plan(InitialCryptoLayout::Contiguous, 1894, Some(124..136), 1150, &mut rng(1)),
        None
    );
}

#[test]
fn chaos_splits_evenly_with_a_head_and_tail_in_the_first_packet() {
    for seed in 0..200 {
        let len = 1500 + (seed as usize * 7) % 600;
        let packets = plan(InitialCryptoLayout::Chaos, len, None, 1150, &mut rng(seed)).unwrap();
        assert_partition(&packets, len);
        assert_eq!(packets.len(), 2, "len {len}");
        let first: usize = packets[0].iter().map(|r| r.len()).sum();
        let second: usize = packets[1].iter().map(|r| r.len()).sum();
        assert!(first.abs_diff(second) <= 1, "{first} vs {second}");
        let head = &packets[0][1];
        assert_eq!(head.start, 0);
        assert!(CHAOS_HEAD.contains(&head.end));
        assert_eq!(packets[0][0].end, len);
    }
}

#[test]
fn a_hello_that_fits_one_packet_is_still_sliced() {
    let packets =
        plan(InitialCryptoLayout::SniSlice, 600, Some(60..72), 1150, &mut rng(1)).unwrap();
    assert_eq!(packets, vec![vec![66..600, 0..66]]);
}

#[test]
fn a_long_hello_spreads_its_middle_over_more_packets() {
    let packets =
        plan(InitialCryptoLayout::SniSlice, 3000, Some(124..136), 1150, &mut rng(1)).unwrap();
    assert_eq!(packets.len(), 3);
    assert_partition(&packets, 3000);
    for p in &packets {
        assert!(p.iter().map(|r| crypto_frame_len(r)).sum::<usize>() <= 1150);
    }
}

#[test]
fn no_room_means_no_plan() {
    assert_eq!(plan(InitialCryptoLayout::Chaos, 1900, None, 200, &mut rng(1)), None);
}

#[test]
fn scatter_keeps_every_byte_and_stays_within_the_spare_room() {
    for seed in 0..500 {
        let ranges = vec![1000..1950, 0..60];
        let base: usize = ranges.iter().map(crypto_frame_len).sum();
        let spare = (seed as usize * 13) % 300;
        let pieces = scatter(ranges, spare, &mut rng(seed));
        let mut crypto = Vec::new();
        let mut size = 0;
        for p in &pieces {
            match p {
                Piece::Crypto(r) => {
                    size += crypto_frame_len(r);
                    crypto.push(r.clone());
                },
                Piece::Ping => size += 1,
                Piece::Padding(n) => {
                    assert!(*n > 0);
                    size += n;
                },
            }
        }
        assert!(size <= base + spare, "seed {seed}: {size} > {base} + {spare}");
        crypto.sort_by_key(|r| r.start);
        let joined: Vec<usize> = crypto.iter().flat_map(|r| r.clone()).collect();
        let expected: Vec<usize> = (0..60).chain(1000..1950).collect();
        assert_eq!(joined, expected, "seed {seed}");
        let frames = crypto.len();
        assert!((2..=2 + CHAOS_MAX_ADDED_CRYPTO).contains(&frames));
    }
}

#[test]
fn scatter_varies_frames_pings_and_order_like_chrome() {
    let (mut max_frames, mut max_pings, mut reordered, mut padded_inside) = (0, 0, false, false);
    for seed in 0..200 {
        let pieces = scatter(vec![1000..1950, 0..60], 200, &mut rng(seed));
        let frames: Vec<&Range<usize>> = pieces
            .iter()
            .filter_map(|p| match p {
                Piece::Crypto(r) => Some(r),
                _ => None,
            })
            .collect();
        max_frames = max_frames.max(frames.len());
        max_pings = max_pings.max(pieces.iter().filter(|p| **p == Piece::Ping).count());
        reordered |= frames
            .windows(2)
            .any(|w| w[0].start > w[1].start && w[0].start != 1000);
        padded_inside |= pieces[1..].iter().any(|p| matches!(p, Piece::Padding(_)));
    }
    assert!(max_frames >= 8, "max CRYPTO frames {max_frames}");
    assert!(max_pings >= 8, "max PINGs {max_pings}");
    assert!(reordered && padded_inside);
}
