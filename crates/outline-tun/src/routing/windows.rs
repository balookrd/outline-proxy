//! Windows IP route and DNS management via IP Helper API (NetIO).
//!
//! Provides route table manipulation and DNS configuration for the TUN
//! interface under Windows, including:
//! - Default route splitting into `0.0.0.0/1` and `128.0.0.0/1`
//! - Host routing to the proxy server via the physical gateway
//! - Interface DNS server configuration
//! - RAII `RouteGuard` for guaranteed cleanup on shutdown or panic.

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};

/// Route entry describing an installed IP route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub prefix: IpAddr,
    pub prefix_len: u8,
    pub nexthop: IpAddr,
    pub if_index: u32,
}

/// RAII guard that removes added routes on drop.
#[derive(Debug)]
pub struct RouteGuard {
    routes: Vec<RouteEntry>,
    active: bool,
}

impl RouteGuard {
    pub fn new() -> Self {
        Self { routes: Vec::new(), active: true }
    }

    pub fn from_routes(routes: Vec<RouteEntry>) -> Self {
        Self { routes, active: true }
    }

    pub fn push(&mut self, entry: RouteEntry) {
        self.routes.push(entry);
    }

    /// Disarms the guard so routes will NOT be deleted when dropped.
    pub fn defuse(&mut self) {
        self.active = false;
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn routes(&self) -> &[RouteEntry] {
        &self.routes
    }
}

impl Default for RouteGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        for entry in self.routes.iter().rev() {
            if let Err(err) =
                delete_route(entry.prefix, entry.prefix_len, entry.nexthop, entry.if_index)
            {
                #[cfg(windows)]
                tracing::warn!(
                    prefix = %entry.prefix,
                    prefix_len = entry.prefix_len,
                    nexthop = %entry.nexthop,
                    if_index = entry.if_index,
                    error = %err,
                    "failed to remove route on RouteGuard drop"
                );
                #[cfg(not(windows))]
                let _ = err;
            }
        }
    }
}

/// Returns the pair of `/1` routes (`0.0.0.0/1` and `128.0.0.0/1`) targeting Wintun.
pub fn default_tunnel_routes_v4(wintun_if_index: u32) -> [RouteEntry; 2] {
    [
        RouteEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 1,
            nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            if_index: wintun_if_index,
        },
        RouteEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
            prefix_len: 1,
            nexthop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            if_index: wintun_if_index,
        },
    ]
}

/// Returns the host route for `server_ip` directed through the physical interface.
pub fn host_route(server_ip: IpAddr, gateway: IpAddr, orig_if_index: u32) -> RouteEntry {
    let prefix_len = if server_ip.is_ipv4() { 32 } else { 128 };
    RouteEntry {
        prefix: server_ip,
        prefix_len,
        nexthop: gateway,
        if_index: orig_if_index,
    }
}

/// Validates that a route entry has a valid prefix length and no host bits set.
pub fn validate_route_entry(entry: &RouteEntry) -> Result<()> {
    match (entry.prefix, entry.nexthop) {
        (IpAddr::V4(prefix_v4), IpAddr::V4(_)) => {
            if entry.prefix_len > 32 {
                bail!("IPv4 prefix length {} exceeds 32", entry.prefix_len);
            }
            if entry.prefix_len < 32 {
                let mask = if entry.prefix_len == 0 {
                    0u32
                } else {
                    !((1u32 << (32 - entry.prefix_len)) - 1)
                };
                let ip_u32 = u32::from(prefix_v4);
                if (ip_u32 & !mask) != 0 {
                    bail!(
                        "IPv4 prefix {} has host bits set outside /{} mask",
                        entry.prefix,
                        entry.prefix_len
                    );
                }
            }
        },
        (IpAddr::V6(prefix_v6), IpAddr::V6(_)) => {
            if entry.prefix_len > 128 {
                bail!("IPv6 prefix length {} exceeds 128", entry.prefix_len);
            }
            if entry.prefix_len < 128 {
                let mask = if entry.prefix_len == 0 {
                    0u128
                } else {
                    !((1u128 << (128 - entry.prefix_len)) - 1)
                };
                let ip_u128 = u128::from(prefix_v6);
                if (ip_u128 & !mask) != 0 {
                    bail!(
                        "IPv6 prefix {} has host bits set outside /{} mask",
                        entry.prefix,
                        entry.prefix_len
                    );
                }
            }
        },
        _ => bail!("mismatched IP families: prefix {} and nexthop {}", entry.prefix, entry.nexthop),
    }
    Ok(())
}

#[cfg(windows)]
pub fn ip_to_sockaddr_inet(ip: IpAddr) -> windows_sys::Win32::Networking::WinSock::SOCKADDR_INET {
    use windows_sys::Win32::Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN,
        SOCKADDR_IN6, SOCKADDR_INET,
    };
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let s_addr = u32::from_ne_bytes(octets);
            let sin_addr = IN_ADDR { S_un: IN_ADDR_0 { S_addr: s_addr } };
            let sin = SOCKADDR_IN {
                sin_family: AF_INET as ADDRESS_FAMILY,
                sin_port: 0,
                sin_addr,
                sin_zero: [0; 8],
            };
            SOCKADDR_INET { Ipv4: sin }
        },
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let sin6_addr = IN6_ADDR { u: IN6_ADDR_0 { Byte: octets } };
            let sin6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6 as ADDRESS_FAMILY,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr,
                Anonymous: unsafe { std::mem::zeroed() },
            };
            SOCKADDR_INET { Ipv6: sin6 }
        },
    }
}

#[cfg(windows)]
pub fn sockaddr_inet_to_ip(
    sock: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET,
) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    let family = unsafe { sock.si_family } as u16;
    if family == AF_INET {
        let sin = unsafe { sock.Ipv4 };
        let s_addr = unsafe { sin.sin_addr.S_un.S_addr };
        let octets = s_addr.to_ne_bytes();
        Some(IpAddr::V4(Ipv4Addr::from(octets)))
    } else if family == AF_INET6 {
        let sin6 = unsafe { sock.Ipv6 };
        let bytes = unsafe { sin6.sin6_addr.u.Byte };
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

#[cfg(windows)]
pub fn route_entry_to_forward_row2(
    entry: &RouteEntry,
    metric: u32,
) -> windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2 {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IP_ADDRESS_PREFIX, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.InterfaceIndex = entry.if_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: ip_to_sockaddr_inet(entry.prefix),
        PrefixLength: entry.prefix_len,
    };
    row.NextHop = ip_to_sockaddr_inet(entry.nexthop);
    row.Metric = metric;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

#[cfg(windows)]
pub fn forward_row2_to_route_entry(
    row: &windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_ROW2,
) -> Option<RouteEntry> {
    let prefix = sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix)?;
    let nexthop = sockaddr_inet_to_ip(&row.NextHop)?;
    Some(RouteEntry {
        prefix,
        prefix_len: row.DestinationPrefix.PrefixLength,
        nexthop,
        if_index: row.InterfaceIndex,
    })
}

#[cfg(windows)]
pub fn get_best_interface(dest: IpAddr) -> Result<(u32, IpAddr)> {
    use std::ptr;
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::SOCKADDR_INET;

    let dest_sock = ip_to_sockaddr_inet(dest);
    let mut best_route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut best_src: SOCKADDR_INET = unsafe { std::mem::zeroed() };

    let err = unsafe {
        GetBestRoute2(ptr::null(), 0, ptr::null(), &dest_sock, 0, &mut best_route, &mut best_src)
    };

    if err != NO_ERROR {
        bail!("GetBestRoute2 failed for destination {dest}: error code {err}");
    }

    let if_index = best_route.InterfaceIndex;
    let nexthop = sockaddr_inet_to_ip(&best_route.NextHop).unwrap_or(match dest {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });

    Ok((if_index, nexthop))
}

#[cfg(not(windows))]
pub fn get_best_interface(_dest: IpAddr) -> Result<(u32, IpAddr)> {
    bail!("get_best_interface is only supported on Windows")
}

#[cfg(windows)]
pub fn add_route(
    prefix: IpAddr,
    prefix_len: u8,
    nexthop: IpAddr,
    if_index: u32,
    metric: u32,
) -> Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, IP_ADDRESS_PREFIX, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.InterfaceIndex = if_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: ip_to_sockaddr_inet(prefix),
        PrefixLength: prefix_len,
    };
    row.NextHop = ip_to_sockaddr_inet(nexthop);
    row.Metric = metric;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Protocol = MIB_IPPROTO_NETMGMT;

    let err = unsafe { CreateIpForwardEntry2(&row) };
    if err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS {
        bail!(
            "CreateIpForwardEntry2 failed for {prefix}/{prefix_len} via {nexthop} on if {if_index}: error code {err}"
        );
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn add_route(
    _prefix: IpAddr,
    _prefix_len: u8,
    _nexthop: IpAddr,
    _if_index: u32,
    _metric: u32,
) -> Result<()> {
    bail!("add_route is only supported on Windows")
}

#[cfg(windows)]
pub fn delete_route(prefix: IpAddr, prefix_len: u8, nexthop: IpAddr, if_index: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        DeleteIpForwardEntry2, IP_ADDRESS_PREFIX, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
    };

    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.InterfaceIndex = if_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: ip_to_sockaddr_inet(prefix),
        PrefixLength: prefix_len,
    };
    row.NextHop = ip_to_sockaddr_inet(nexthop);

    let err = unsafe { DeleteIpForwardEntry2(&row) };
    if err != NO_ERROR && err != ERROR_NOT_FOUND && err != ERROR_FILE_NOT_FOUND {
        bail!(
            "DeleteIpForwardEntry2 failed for {prefix}/{prefix_len} via {nexthop} on if {if_index}: error code {err}"
        );
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn delete_route(
    _prefix: IpAddr,
    _prefix_len: u8,
    _nexthop: IpAddr,
    _if_index: u32,
) -> Result<()> {
    bail!("delete_route is only supported on Windows")
}

#[cfg(windows)]
pub fn set_interface_dns(if_index: u32, dns_servers: &[IpAddr]) -> Result<()> {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid, DNS_INTERFACE_SETTINGS,
        DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, SetInterfaceDnsSettings,
    };

    if dns_servers.is_empty() {
        return Ok(());
    }

    // Try SetInterfaceDnsSettings first
    let mut luid = unsafe { std::mem::zeroed() };
    let luid_err = unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) };
    if luid_err == NO_ERROR {
        let mut guid = unsafe { std::mem::zeroed() };
        let guid_err = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
        if guid_err == NO_ERROR {
            let dns_str = dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut wide_dns: Vec<u16> = dns_str.encode_utf16().chain(std::iter::once(0)).collect();

            let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
            settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
            settings.Flags = DNS_SETTING_NAMESERVER as u64;
            settings.NameServer = wide_dns.as_mut_ptr();

            let err = unsafe { SetInterfaceDnsSettings(guid, &settings) };
            if err == NO_ERROR {
                tracing::info!(
                    if_index,
                    %dns_str,
                    "DNS servers configured via SetInterfaceDnsSettings"
                );
                return Ok(());
            }
            tracing::warn!(
                if_index,
                error_code = err,
                "SetInterfaceDnsSettings failed; falling back to netsh"
            );
        }
    }

    // Fallback: netsh interface ipv4/ipv6 set/add dnsservers
    for (i, &dns) in dns_servers.iter().enumerate() {
        let proto = if dns.is_ipv4() { "ipv4" } else { "ipv6" };
        let if_arg = format!("name={if_index}");
        let addr_arg = format!("address={dns}");

        if i == 0 {
            let status = std::process::Command::new("netsh")
                .args([
                    "interface",
                    proto,
                    "set",
                    "dnsservers",
                    &if_arg,
                    "source=static",
                    &addr_arg,
                    "validate=no",
                ])
                .status()
                .with_context(|| format!("failed to execute netsh to set primary {proto} DNS"))?;

            if !status.success() {
                bail!("netsh set dnsservers failed with status {status}");
            }
        } else {
            let idx_arg = format!("index={}", i + 1);
            let status = std::process::Command::new("netsh")
                .args([
                    "interface",
                    proto,
                    "add",
                    "dnsservers",
                    &if_arg,
                    &addr_arg,
                    &idx_arg,
                    "validate=no",
                ])
                .status()
                .with_context(|| format!("failed to execute netsh to add secondary {proto} DNS"))?;

            if !status.success() {
                tracing::warn!(if_index, %dns, "failed to add secondary DNS server via netsh");
            }
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn set_interface_dns(_if_index: u32, _dns_servers: &[IpAddr]) -> Result<()> {
    bail!("set_interface_dns is only supported on Windows")
}

#[cfg(windows)]
pub fn setup_windows_routes(server_ip: IpAddr, wintun_if_index: u32) -> Result<RouteGuard> {
    let (orig_if_index, gateway) = get_best_interface(server_ip)
        .context("failed to determine default interface and gateway for server IP")?;
    setup_windows_routes_with_gateway(server_ip, gateway, orig_if_index, wintun_if_index)
}

#[cfg(windows)]
pub fn setup_windows_routes_with_gateway(
    server_ip: IpAddr,
    gateway: IpAddr,
    orig_if_index: u32,
    wintun_if_index: u32,
) -> Result<RouteGuard> {
    let mut guard = RouteGuard::new();

    // 1. Host route to proxy server via original physical interface & gateway.
    // Metric 1 ensures it is preferred over default routes.
    let host_prefix_len = if server_ip.is_ipv4() { 32 } else { 128 };
    add_route(server_ip, host_prefix_len, gateway, orig_if_index, 1).with_context(|| {
        format!("failed to add host route to {server_ip} on interface {orig_if_index}")
    })?;
    guard.push(RouteEntry {
        prefix: server_ip,
        prefix_len: host_prefix_len,
        nexthop: gateway,
        if_index: orig_if_index,
    });

    // 2. Pair of /1 routes covering all IPv4 (0.0.0.0/1 and 128.0.0.0/1) via Wintun interface.
    let tunnel_routes = default_tunnel_routes_v4(wintun_if_index);
    for entry in tunnel_routes {
        if let Err(err) =
            add_route(entry.prefix, entry.prefix_len, entry.nexthop, entry.if_index, 0)
        {
            return Err(err).with_context(|| {
                format!(
                    "failed to add tunnel route {}/{} on interface {}",
                    entry.prefix, entry.prefix_len, entry.if_index
                )
            });
        }
        guard.push(entry);
    }

    tracing::info!(
        %server_ip,
        %gateway,
        orig_if_index,
        wintun_if_index,
        "Windows routes successfully installed for TUN"
    );

    Ok(guard)
}

#[cfg(windows)]
pub fn setup_windows_routes_multi(
    server_ips: &[IpAddr],
    wintun_if_index: u32,
) -> Result<RouteGuard> {
    let mut guard = RouteGuard::new();

    // 1. Host route to each proxy server via original physical interface & gateway.
    for &server_ip in server_ips {
        if let Ok((orig_if_index, gateway)) = get_best_interface(server_ip) {
            let host_prefix_len = if server_ip.is_ipv4() { 32 } else { 128 };
            if let Ok(()) = add_route(server_ip, host_prefix_len, gateway, orig_if_index, 1) {
                guard.push(RouteEntry {
                    prefix: server_ip,
                    prefix_len: host_prefix_len,
                    nexthop: gateway,
                    if_index: orig_if_index,
                });
            }
        }
    }

    // 2. Pair of /1 routes covering all IPv4 (0.0.0.0/1 and 128.0.0.0/1) via Wintun interface.
    let tunnel_routes = default_tunnel_routes_v4(wintun_if_index);
    for entry in tunnel_routes {
        if let Err(err) =
            add_route(entry.prefix, entry.prefix_len, entry.nexthop, entry.if_index, 0)
        {
            return Err(err).with_context(|| {
                format!(
                    "failed to add tunnel route {}/{} on interface {}",
                    entry.prefix, entry.prefix_len, entry.if_index
                )
            });
        }
        guard.push(entry);
    }

    tracing::info!(
        server_count = server_ips.len(),
        wintun_if_index,
        "Windows routes successfully installed for TUN"
    );

    Ok(guard)
}

#[cfg(not(windows))]
pub fn setup_windows_routes(_server_ip: IpAddr, _wintun_if_index: u32) -> Result<RouteGuard> {
    bail!("setup_windows_routes is only supported on Windows")
}

#[cfg(not(windows))]
pub fn setup_windows_routes_multi(
    _server_ips: &[IpAddr],
    _wintun_if_index: u32,
) -> Result<RouteGuard> {
    bail!("setup_windows_routes_multi is only supported on Windows")
}

#[cfg(not(windows))]
pub fn setup_windows_routes_with_gateway(
    _server_ip: IpAddr,
    _gateway: IpAddr,
    _orig_if_index: u32,
    _wintun_if_index: u32,
) -> Result<RouteGuard> {
    bail!("setup_windows_routes_with_gateway is only supported on Windows")
}

#[cfg(test)]
#[path = "tests/windows.rs"]
mod tests;
