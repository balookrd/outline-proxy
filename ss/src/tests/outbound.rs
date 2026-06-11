use super::*;

#[test]
fn parses_and_preserves_prefix() {
    let p: Ipv6Prefix = "2001:db8:dead::1/64".parse().unwrap();
    assert_eq!(p.to_string(), "2001:db8:dead::/64");

    let expected_net: Ipv6Addr = "2001:db8:dead::".parse().unwrap();
    for _ in 0..64 {
        let a = p.random_addr().unwrap();
        assert_eq!(&a.octets()[..8], &expected_net.octets()[..8]);
    }
}

#[test]
fn handles_non_byte_aligned_prefix() {
    let p: Ipv6Prefix = "2001:db8::/60".parse().unwrap();
    let expected_net: Ipv6Addr = "2001:db8::".parse().unwrap();
    let expected_bits = u128::from_be_bytes(expected_net.octets());
    for _ in 0..32 {
        let a = p.random_addr().unwrap();
        let got = u128::from_be_bytes(a.octets());
        let mask: u128 = !0u128 << (128 - 60);
        assert_eq!(got & mask, expected_bits & mask);
    }
}

#[test]
fn rejects_bad_input() {
    assert!("not-a-cidr".parse::<Ipv6Prefix>().is_err());
    assert!("2001:db8::/200".parse::<Ipv6Prefix>().is_err());
    assert!("10.0.0.0/8".parse::<Ipv6Prefix>().is_err());
}

#[test]
fn enumerate_returns_only_global_unicast() {
    let names = ["lo", "lo0"];
    for name in names {
        if let Ok(addrs) = enumerate_ipv6_on_interface(name) {
            for a in addrs {
                assert_eq!(
                    a.segments()[0] & 0xe000,
                    0x2000,
                    "enumerate returned non-global address {a}",
                );
            }
        }
    }
}

use std::sync::atomic::{AtomicU16, Ordering};

/// A `generate` closure that hands out a fresh, deterministic IPv6 address on
/// each *call* — letting a test distinguish a sticky reuse (closure not called)
/// from a regeneration (closure called, new address).
fn seq_gen(counter: &AtomicU16) -> impl FnOnce() -> std::io::Result<Option<Ipv6Addr>> + '_ {
    move || {
        let n = counter.fetch_add(1, Ordering::Relaxed);
        Ok(Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)))
    }
}

#[test]
fn sticky_pins_source_per_destination() {
    let cache = StickyIpv6Cache::with_cap(100, 1024);
    let counter = AtomicU16::new(1);
    let dest_a: IpAddr = "2606:4700::1".parse().unwrap();
    let dest_b: IpAddr = "2607:6bc0::10".parse().unwrap();

    let a1 = cache.source_for(dest_a, 1000, seq_gen(&counter)).unwrap().unwrap();
    let a2 = cache.source_for(dest_a, 1050, seq_gen(&counter)).unwrap().unwrap();
    assert_eq!(a1, a2, "same destination within TTL must reuse the pinned source");

    let b1 = cache.source_for(dest_b, 1050, seq_gen(&counter)).unwrap().unwrap();
    assert_ne!(a1, b1, "distinct destinations get independent pins");
}

#[test]
fn sticky_regenerates_after_ttl() {
    let cache = StickyIpv6Cache::with_cap(100, 1024);
    let counter = AtomicU16::new(1);
    let dest: IpAddr = "2606:4700::1".parse().unwrap();

    let first = cache.source_for(dest, 1000, seq_gen(&counter)).unwrap().unwrap();
    // `now` is past expiry (1000 + 100 ttl): the pin is regenerated.
    let second = cache.source_for(dest, 1200, seq_gen(&counter)).unwrap().unwrap();
    assert_ne!(first, second, "an expired pin must be regenerated");
    let third = cache.source_for(dest, 1250, seq_gen(&counter)).unwrap().unwrap();
    assert_eq!(second, third, "the regenerated pin sticks for a fresh TTL");
}

#[test]
fn sticky_empty_pool_falls_back_to_none() {
    let cache = StickyIpv6Cache::with_cap(100, 1024);
    let dest: IpAddr = "2606:4700::1".parse().unwrap();
    let none = cache.source_for(dest, 1000, || Ok(None)).unwrap();
    assert!(none.is_none(), "empty pool yields None (kernel default), no pin stored");

    let counter = AtomicU16::new(7);
    let got = cache.source_for(dest, 1001, seq_gen(&counter)).unwrap().unwrap();
    assert_eq!(got, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7));
}

#[test]
fn sticky_stays_within_cap() {
    let cache = StickyIpv6Cache::with_cap(100, 2);
    let counter = AtomicU16::new(1);
    for host in 1u16..=5 {
        let dest = IpAddr::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, host));
        cache
            .source_for(dest, 1000 + u64::from(host), seq_gen(&counter))
            .unwrap();
    }
    assert!(cache.map.len() <= 2, "cache must stay within its capacity bound");
}
