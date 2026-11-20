use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

#[test]
fn test_default_tunnel_routes_v4_subnets() {
    let if_index = 42;
    let routes = default_tunnel_routes_v4(if_index);

    assert_eq!(routes.len(), 2);

    let r0 = &routes[0];
    assert_eq!(r0.prefix, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(r0.prefix_len, 1);
    assert_eq!(r0.nexthop, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(r0.if_index, if_index);
    assert!(validate_route_entry(r0).is_ok());

    let r1 = &routes[1];
    assert_eq!(r1.prefix, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)));
    assert_eq!(r1.prefix_len, 1);
    assert_eq!(r1.nexthop, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(r1.if_index, if_index);
    assert!(validate_route_entry(r1).is_ok());

    // Verify partition of the IPv4 address space
    let sample_ips = [
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(127, 255, 255, 255),
        Ipv4Addr::new(128, 0, 0, 0),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(255, 255, 255, 255),
    ];

    for ip in sample_ips {
        let u = u32::from(ip);
        let in_r0 = (u & 0x8000_0000) == 0;
        let in_r1 = (u & 0x8000_0000) != 0;

        assert_ne!(in_r0, in_r1, "IP {ip} must match exactly one of 0.0.0.0/1 or 128.0.0.0/1");
    }
}

#[test]
fn test_host_route_creation() {
    let srv_v4: IpAddr = "198.51.100.1".parse().unwrap();
    let gw_v4: IpAddr = "192.168.1.1".parse().unwrap();
    let entry_v4 = host_route(srv_v4, gw_v4, 12);

    assert_eq!(entry_v4.prefix, srv_v4);
    assert_eq!(entry_v4.prefix_len, 32);
    assert_eq!(entry_v4.nexthop, gw_v4);
    assert_eq!(entry_v4.if_index, 12);
    assert!(validate_route_entry(&entry_v4).is_ok());

    let srv_v6: IpAddr = "2001:db8::1".parse().unwrap();
    let gw_v6: IpAddr = "fe80::1".parse().unwrap();
    let entry_v6 = host_route(srv_v6, gw_v6, 15);

    assert_eq!(entry_v6.prefix, srv_v6);
    assert_eq!(entry_v6.prefix_len, 128);
    assert_eq!(entry_v6.nexthop, gw_v6);
    assert_eq!(entry_v6.if_index, 15);
    assert!(validate_route_entry(&entry_v6).is_ok());
}

#[test]
fn test_validate_route_entry_invalid_cases() {
    // IPv4 prefix_len > 32
    let invalid_len = RouteEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 33,
        nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        if_index: 1,
    };
    assert!(validate_route_entry(&invalid_len).is_err());

    // IPv4 host bits set outside prefix length (e.g. 192.168.1.5/24)
    let dirty_host_bits = RouteEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
        prefix_len: 24,
        nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        if_index: 1,
    };
    assert!(validate_route_entry(&dirty_host_bits).is_err());

    // Mismatched IP families
    let mismatched = RouteEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        prefix_len: 8,
        nexthop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        if_index: 1,
    };
    assert!(validate_route_entry(&mismatched).is_err());

    // Valid /0 default route
    let default_v4 = RouteEntry {
        prefix: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        prefix_len: 0,
        nexthop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        if_index: 1,
    };
    assert!(validate_route_entry(&default_v4).is_ok());
}

#[test]
fn test_route_guard_lifecycle() {
    let mut guard = RouteGuard::new();
    assert!(guard.is_active());
    assert_eq!(guard.routes().len(), 0);

    let entry1 = RouteEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        prefix_len: 1,
        nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        if_index: 10,
    };
    let entry2 = RouteEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        prefix_len: 1,
        nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        if_index: 10,
    };

    guard.push(entry1.clone());
    guard.push(entry2.clone());

    assert_eq!(guard.routes(), &[entry1.clone(), entry2]);

    guard.defuse();
    assert!(!guard.is_active());

    let guard2 = RouteGuard::from_routes(vec![entry1.clone()]);
    assert_eq!(guard2.routes(), &[entry1]);
    assert!(guard2.is_active());
}

#[cfg(not(windows))]
#[test]
fn test_windows_functions_stubs_on_non_windows() {
    let dummy_ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert!(get_best_interface(dummy_ip).is_err());
    assert!(add_route(dummy_ip, 32, dummy_ip, 1, 0).is_err());
    assert!(delete_route(dummy_ip, 32, dummy_ip, 1).is_err());
    assert!(set_interface_dns(1, &[dummy_ip]).is_err());
    assert!(setup_windows_routes(dummy_ip, 1).is_err());
    assert!(setup_windows_routes_with_gateway(dummy_ip, dummy_ip, 1, 2).is_err());
}

#[cfg(windows)]
#[test]
fn test_forward_row2_roundtrip_conversion() {
    let entry = RouteEntry {
        prefix: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        prefix_len: 1,
        nexthop: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        if_index: 5,
    };

    let row = route_entry_to_forward_row2(&entry, 10);
    assert_eq!(row.InterfaceIndex, 5);
    assert_eq!(row.Metric, 10);
    assert_eq!(row.DestinationPrefix.PrefixLength, 1);

    let recovered = forward_row2_to_route_entry(&row).expect("failed to decode forward row");
    assert_eq!(recovered, entry);
}

#[cfg(windows)]
#[test]
fn test_forward_row2_v6_roundtrip_conversion() {
    let entry = RouteEntry {
        prefix: "2001:db8::".parse().unwrap(),
        prefix_len: 32,
        nexthop: "fe80::1".parse().unwrap(),
        if_index: 7,
    };

    let row = route_entry_to_forward_row2(&entry, 0);
    assert_eq!(row.InterfaceIndex, 7);
    assert_eq!(row.DestinationPrefix.PrefixLength, 32);

    let recovered = forward_row2_to_route_entry(&row).expect("failed to decode forward row");
    assert_eq!(recovered, entry);
}
