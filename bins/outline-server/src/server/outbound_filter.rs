//! Outbound address filtering to prevent Server-Side Request Forgery (SSRF).
//!
//! When enabled (`block_private_ips = true`), outbound TCP and UDP dials
//! to loopback, private, link-local, unspecified, multicast, broadcast,
//! and cloud metadata IP addresses are rejected unless explicitly allowed
//! by `allowed_subnets`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{Result, bail};
use outline_net::IpAliasTable;

#[derive(Clone, Debug, Default)]
pub(in crate::server) struct OutboundFilter {
    block_private_ips: bool,
    allowed_subnets: Option<Arc<IpAliasTable>>,
}

impl OutboundFilter {
    pub(in crate::server) fn new(
        block_private_ips: bool,
        allowed_subnets: &[String],
    ) -> Result<Self> {
        let allowed = if allowed_subnets.is_empty() {
            None
        } else {
            let table = IpAliasTable::build([("allowed", allowed_subnets)])
                .map_err(|e| anyhow::anyhow!("invalid allowed_subnets: {e}"))?;
            Some(Arc::new(table))
        };

        Ok(Self {
            block_private_ips,
            allowed_subnets: allowed,
        })
    }

    pub(in crate::server) fn is_blocked(&self, ip: IpAddr) -> bool {
        if !self.block_private_ips {
            return false;
        }

        let canonical = ip.to_canonical();

        // If the address matches an explicitly allowed subnet, permit it.
        if let Some(allowed) = &self.allowed_subnets
            && allowed.resolve(canonical).is_some()
        {
            return false;
        }

        is_private_or_local(canonical)
    }

    pub(in crate::server) fn check_ip(&self, ip: IpAddr) -> Result<()> {
        if self.is_blocked(ip) {
            bail!("outbound connection to blocked IP {ip} is prohibited by SSRF filter");
        }
        Ok(())
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback() // 127.0.0.0/8
        || v4.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || v4.is_link_local() // 169.254.0.0/16 (covers 169.254.169.254 metadata)
        || v4.is_broadcast() // 255.255.255.255
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_multicast() // 224.0.0.0/4
        // Shared address space / CGNAT: 100.64.0.0/10
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        // Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        // Benchmarking: 198.18.0.0/15
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    let seg = v6.segments();
    v6.is_loopback() // ::1
        || v6.is_unspecified() // ::
        || v6.is_multicast() // ff00::/8
        // Unique Local Address (ULA): fc00::/7 (covers fd00:ec2::254 metadata)
        || ((seg[0] & 0xfe00) == 0xfc00)
        // Link-local unicast: fe80::/10
        || ((seg[0] & 0xffc0) == 0xfe80)
        // Documentation: 2001:db8::/32
        || (seg[0] == 0x2001 && seg[1] == 0xdb8)
}

fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn disabled_filter_allows_all() {
        let filter = OutboundFilter::new(false, &[]).unwrap();
        assert!(!filter.is_blocked(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!filter.is_blocked(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(!filter.is_blocked(IpAddr::from_str("169.254.169.254").unwrap()));
        assert!(!filter.is_blocked(IpAddr::from_str("::1").unwrap()));
    }

    #[test]
    fn blocks_loopback_and_private_v4() {
        let filter = OutboundFilter::new(true, &[]).unwrap();
        assert!(filter.is_blocked(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("127.1.2.3").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("172.16.0.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("172.31.255.255").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("192.168.1.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("169.254.169.254").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("0.0.0.0").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("255.255.255.255").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("100.64.0.1").unwrap())); // CGNAT

        // Public IPs allowed
        assert!(!filter.is_blocked(IpAddr::from_str("1.1.1.1").unwrap()));
        assert!(!filter.is_blocked(IpAddr::from_str("8.8.8.8").unwrap()));
    }

    #[test]
    fn blocks_loopback_and_private_v6() {
        let filter = OutboundFilter::new(true, &[]).unwrap();
        assert!(filter.is_blocked(IpAddr::from_str("::1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("::").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("fe80::1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("fc00::1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("fd00:ec2::254").unwrap())); // AWS metadata
        assert!(filter.is_blocked(IpAddr::from_str("ff02::1").unwrap())); // Multicast

        // Public IPv6 allowed
        assert!(!filter.is_blocked(IpAddr::from_str("2606:4700:4700::1111").unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6() {
        let filter = OutboundFilter::new(true, &[]).unwrap();
        assert!(filter.is_blocked(IpAddr::from_str("::ffff:127.0.0.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("::ffff:10.0.0.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("::ffff:169.254.169.254").unwrap()));

        // Public IPv4 mapped allowed
        assert!(!filter.is_blocked(IpAddr::from_str("::ffff:1.1.1.1").unwrap()));
    }

    #[test]
    fn allowed_subnets_whitelist() {
        let filter = OutboundFilter::new(
            true,
            &["192.168.1.0/24".to_string(), "127.0.0.1".to_string(), "fd00:ec2::/64".to_string()],
        )
        .unwrap();

        // Whitelisted
        assert!(!filter.is_blocked(IpAddr::from_str("192.168.1.50").unwrap()));
        assert!(!filter.is_blocked(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(!filter.is_blocked(IpAddr::from_str("fd00:ec2::254").unwrap()));

        // Other private still blocked
        assert!(filter.is_blocked(IpAddr::from_str("192.168.2.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("10.0.0.1").unwrap()));
        assert!(filter.is_blocked(IpAddr::from_str("127.0.0.2").unwrap()));
    }
}
