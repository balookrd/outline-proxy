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
