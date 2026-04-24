//! Outbound source-address selection for upstream TCP/UDP connections.
//!
//! Two modes are supported:
//!
//! - [`Ipv6Prefix`]: a CIDR configured statically; each new upstream socket
//!   binds to a random address drawn from the prefix. Requires either
//!   `IPV6_FREEBIND` (set automatically on Linux) with the prefix on-link on
//!   an interface, or an AnyIP route (`ip -6 route add local <prefix> dev lo`).
//!
//! - [`InterfaceSource`]: enumerate the IPv6 addresses currently assigned to a
//!   named interface and pick one at random. Useful for DHCPv6/SLAAC
//!   deployments where the exact addresses/prefix are not known up-front, and
//!   especially well suited to kernel privacy extensions
//!   (`net.ipv6.conf.<iface>.use_tempaddr=2`): every rotated temporary address
//!   appears on the interface and is picked up on the next refresh without a
//!   restart. Only addresses actually assigned to the interface are used, so
//!   inbound return traffic works under ordinary SLAAC (no AnyIP route, no
//!   NDP proxy, no IPV6_FREEBIND needed).
//!
//! At the call site the two modes are unified behind [`OutboundIpv6`].

use std::{
    net::Ipv6Addr,
    num::ParseIntError,
    str::FromStr,
    sync::Arc,
};

use parking_lot::RwLock;
use serde::{Deserialize, Deserializer};
use thiserror::Error;

// ── Ipv6 prefix ──────────────────────────────────────────────────────────────

/// IPv6 address prefix (CIDR) used as the pool for random outbound source
/// selection. Only IPv6 is supported; IPv4 continues to use the kernel default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Prefix {
    network: Ipv6Addr,
    prefix_len: u8,
}

#[derive(Debug, Error)]
pub enum Ipv6PrefixParseError {
    #[error("expected CIDR notation 'addr/len', got {0:?}")]
    Format(String),
    #[error("invalid IPv6 address: {0}")]
    Addr(#[from] std::net::AddrParseError),
    #[error("invalid prefix length: {0}")]
    Len(#[from] ParseIntError),
    #[error("prefix length {0} out of range (0..=128)")]
    LenRange(u8),
}

impl Ipv6Prefix {
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Result<Self, Ipv6PrefixParseError> {
        if prefix_len > 128 {
            return Err(Ipv6PrefixParseError::LenRange(prefix_len));
        }
        let network = mask_to_prefix(addr, prefix_len);
        Ok(Self { network, prefix_len })
    }

    #[allow(dead_code)]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    #[allow(dead_code)]
    pub fn network(&self) -> Ipv6Addr {
        self.network
    }

    /// Returns a random IPv6 address from the prefix. The top `prefix_len`
    /// bits are preserved; the remaining host bits are filled with
    /// cryptographically-strong random bytes.
    pub fn random_addr(&self) -> std::io::Result<Ipv6Addr> {
        let mut random = [0_u8; 16];
        fill_random(&mut random)?;
        let net = self.network.octets();
        let mut out = [0_u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            let keep = prefix_keep_byte(i, self.prefix_len);
            *slot = (net[i] & keep) | (random[i] & !keep);
        }
        Ok(Ipv6Addr::from(out))
    }
}

fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new()
        .fill(buf)
        .map_err(|error| std::io::Error::other(format!("rng failure: {error:?}")))
}

fn prefix_keep_byte(byte_index: usize, prefix_len: u8) -> u8 {
    let bit_index = (byte_index as u32) * 8;
    let keep_bits = prefix_len as u32;
    if bit_index >= keep_bits {
        0
    } else if keep_bits - bit_index >= 8 {
        0xFF
    } else {
        let k = keep_bits - bit_index; // 1..=7
        0xFFu8 << (8 - k)
    }
}

fn mask_to_prefix(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let octets = addr.octets();
    let mut out = [0_u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = octets[i] & prefix_keep_byte(i, prefix_len);
    }
    Ipv6Addr::from(out)
}

impl FromStr for Ipv6Prefix {
    type Err = Ipv6PrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr, len) = s
            .split_once('/')
            .ok_or_else(|| Ipv6PrefixParseError::Format(s.to_owned()))?;
        let addr: Ipv6Addr = addr.trim().parse()?;
        let prefix_len: u8 = len.trim().parse()?;
        Self::new(addr, prefix_len)
    }
}

impl std::fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl<'de> Deserialize<'de> for Ipv6Prefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ── Interface source ─────────────────────────────────────────────────────────

/// Pool of IPv6 **addresses** currently assigned to a named interface, as
/// reported by `getifaddrs(3)`. Only global-unicast (2000::/3) addresses are
/// kept. Each outbound socket binds to one randomly-picked address from the
/// pool — which means inbound return traffic always lands on an address the
/// host genuinely owns and the kernel answers NDP for, so this mode works
/// under plain SLAAC / DHCPv6 without AnyIP routing or NDP proxying.
///
/// Rotation semantics mirror whatever the kernel does on the interface: if
/// privacy extensions are enabled (`net.ipv6.conf.<iface>.use_tempaddr=2`),
/// each rotated temporary address is discovered on the next refresh cycle
/// and starts (resp. stops) being used as a source.
pub(crate) struct InterfaceSource {
    name: String,
    cache: RwLock<Arc<[Ipv6Addr]>>,
}

impl InterfaceSource {
    pub(crate) fn bind(name: String) -> std::io::Result<Arc<Self>> {
        let initial = enumerate_ipv6_on_interface(&name)?;
        if initial.is_empty() {
            tracing::warn!(
                interface = %name,
                "no usable global IPv6 addresses found on interface at startup; \
                 random outbound source selection will be a no-op until addresses appear"
            );
        } else {
            tracing::info!(
                interface = %name,
                addresses = initial.len(),
                example = %initial[0],
                "discovered IPv6 addresses on outbound interface"
            );
        }
        Ok(Arc::new(Self {
            name,
            cache: RwLock::new(Arc::from(initial.into_boxed_slice())),
        }))
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn snapshot(&self) -> Arc<[Ipv6Addr]> {
        Arc::clone(&self.cache.read())
    }

    /// Re-enumerate the interface and atomically swap the cached address list.
    /// Logs at INFO when the set changes.
    pub(crate) fn refresh(&self) {
        let addrs = match enumerate_ipv6_on_interface(&self.name) {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(
                    interface = %self.name,
                    %error,
                    "failed to enumerate IPv6 addresses on outbound interface; \
                     keeping previous cached set",
                );
                return;
            },
        };
        let current = self.cache.read().clone();
        if addrs.as_slice() != &*current {
            tracing::info!(
                interface = %self.name,
                before = current.len(),
                after = addrs.len(),
                "refreshed outbound IPv6 address pool",
            );
            *self.cache.write() = Arc::from(addrs.into_boxed_slice());
        }
    }

    /// Pick a random address from the cached pool. Returns `None` when the
    /// pool is empty (e.g. interface has no global v6 addresses yet).
    pub(crate) fn random_addr(&self) -> std::io::Result<Option<Ipv6Addr>> {
        let snap = self.snapshot();
        if snap.is_empty() {
            return Ok(None);
        }
        let mut b = [0_u8; 8];
        fill_random(&mut b)?;
        let idx = (u64::from_ne_bytes(b) as usize) % snap.len();
        Ok(Some(snap[idx]))
    }
}

// ── Unified selector ─────────────────────────────────────────────────────────

/// Runtime handle for outbound IPv6 source selection. Either a statically
/// configured prefix or a live-refreshed interface address pool.
pub(crate) enum OutboundIpv6 {
    Prefix(Ipv6Prefix),
    Interface(Arc<InterfaceSource>),
}

impl OutboundIpv6 {
    /// Returns a random outbound IPv6 address, or `None` when the configured
    /// source currently has no usable addresses (interface-based sources only).
    pub(crate) fn random_addr(&self) -> std::io::Result<Option<Ipv6Addr>> {
        match self {
            OutboundIpv6::Prefix(p) => p.random_addr().map(Some),
            OutboundIpv6::Interface(i) => i.random_addr(),
        }
    }
}

impl std::fmt::Display for OutboundIpv6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundIpv6::Prefix(p) => write!(f, "prefix:{p}"),
            OutboundIpv6::Interface(i) => write!(f, "interface:{}", i.name()),
        }
    }
}

// ── Interface enumeration ────────────────────────────────────────────────────

/// Enumerate global-unicast IPv6 **addresses** assigned to `iface` via
/// `getifaddrs(3)`. Link-local, loopback, unique-local, multicast, IPv4-mapped
/// and other non-global ranges are filtered out. Duplicates are collapsed.
/// Available on Linux and macOS; other platforms return an error at bind
/// time (no way to enumerate without a parallel netlink/route-socket impl).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn enumerate_ipv6_on_interface(iface: &str) -> std::io::Result<Vec<Ipv6Addr>> {
    use std::ffi::CStr;

    struct IfAddrsGuard(*mut libc::ifaddrs);
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { libc::freeifaddrs(self.0) };
            }
        }
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a freshly-allocated linked list into `head`
    // when it returns 0. We own the list until freeifaddrs, which the RAII
    // guard guarantees to call even on early return.
    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let _guard = IfAddrsGuard(head);

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is valid while the guard holds the list and until we
        // advance past it; dereferencing is sound.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated C string produced by the libc.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
        if name.to_bytes() != iface.as_bytes() {
            continue;
        }
        // SAFETY: we just checked ifa_addr is non-null.
        let family = unsafe { (*ifa.ifa_addr).sa_family };
        if family as i32 != libc::AF_INET6 {
            continue;
        }
        // SAFETY: with family == AF_INET6, ifa_addr points to a sockaddr_in6.
        let sa6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
        let addr = Ipv6Addr::from(sa6.sin6_addr.s6_addr);

        // Only accept global unicast (2000::/3). This rejects, in one go:
        // loopback (::1), unspecified (::), link-local (fe80::/10),
        // unique-local (fc00::/7), multicast (ff00::/8), IPv4-mapped
        // (::ffff:0:0/96), discard (100::/64) and every other non-global
        // carve-out. `Ipv6Addr::is_global()` would do the same but is still
        // unstable on stable Rust.
        if (addr.segments()[0] & 0xe000) != 0x2000 {
            continue;
        }

        if seen.insert(addr) {
            out.push(addr);
        }
    }
    Ok(out)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn enumerate_ipv6_on_interface(_iface: &str) -> std::io::Result<Vec<Ipv6Addr>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "interface-based outbound IPv6 selection is only supported on Linux and macOS",
    ))
}

// ── IPV6_FREEBIND ────────────────────────────────────────────────────────────

/// Enable `IPV6_FREEBIND` on the given file descriptor so a bind() to an
/// address that is not assigned to any local interface succeeds. Linux-only;
/// on other Unix-like systems this is a no-op and the caller must rely on the
/// address being locally assigned (e.g. via AnyIP routes, or in the
/// interface-based mode the address already being present on the link).
#[cfg(target_os = "linux")]
pub(crate) fn set_ipv6_freebind<T>(socket: &T) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    let value: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_FREEBIND,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_ipv6_freebind<T>(_socket: &T) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_preserves_prefix() {
        let p: Ipv6Prefix = "2001:db8:dead::1/64".parse().unwrap();
        assert_eq!(p.prefix_len(), 64);
        assert_eq!(p.network(), "2001:db8:dead::".parse::<Ipv6Addr>().unwrap());

        for _ in 0..64 {
            let a = p.random_addr().unwrap();
            let net = a.octets();
            assert_eq!(&net[..8], &p.network().octets()[..8]);
        }
    }

    #[test]
    fn handles_non_byte_aligned_prefix() {
        let p: Ipv6Prefix = "2001:db8::/60".parse().unwrap();
        for _ in 0..32 {
            let a = p.random_addr().unwrap();
            let got = u128::from_be_bytes(a.octets());
            let expected = u128::from_be_bytes(p.network().octets());
            let mask: u128 = !0u128 << (128 - 60);
            assert_eq!(got & mask, expected & mask);
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
}
