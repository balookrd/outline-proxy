use std::net::{Ipv4Addr, Ipv6Addr};

use socks5_proto::TargetAddr;

use crate::routing::{is_ipsec_port, target_port};

#[test]
fn ipsec_well_known_ports_are_recognised() {
    assert!(is_ipsec_port(500));
    assert!(is_ipsec_port(4500));
}

#[test]
fn non_ipsec_ports_are_rejected() {
    for port in [0u16, 53, 80, 443, 1701, 1812, 4499, 4501, 65_535] {
        assert!(!is_ipsec_port(port), "port {port} unexpectedly matched IPsec");
    }
}

#[test]
fn target_port_extracts_for_all_target_variants() {
    let v4 = TargetAddr::IpV4(Ipv4Addr::new(10, 0, 0, 1), 4500);
    assert_eq!(target_port(&v4), 4500);

    let v6 = TargetAddr::IpV6(Ipv6Addr::LOCALHOST, 500);
    assert_eq!(target_port(&v6), 500);

    let domain = TargetAddr::Domain("epdg.example.com".to_string(), 4500);
    assert_eq!(target_port(&domain), 4500);
}
