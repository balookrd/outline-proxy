//! `virtio_net_hdr` framing for a TUN device opened with `IFF_VNET_HDR`.
//!
//! When the TUN fd carries the vnet header, every `read(2)` and `write(2)`
//! is prefixed with a fixed 10-byte [`VirtioNetHdr`] describing checksum and
//! GSO offload for the IP packet that follows. Phase 0 only ever emits
//! [`VirtioNetHdr::NONE`] (no checksum offload, no segmentation) so the wire
//! behaviour is identical to the plain path — the header is pure plumbing that
//! the later TSO work builds on.
//!
//! Field byte order is the host's native endianness: the kernel tun/tap driver
//! reads these fields in host order (unlike a virtio device negotiated over a
//! transport), so we (de)serialise with `to_ne_bytes` / `from_ne_bytes`.

/// Size of the legacy `virtio_net_hdr` (no `num_buffers`) as used by TUN with
/// `IFF_VNET_HDR` and the default header size.
pub(crate) const VIRTIO_NET_HDR_LEN: usize = 10;

/// `flags`: the packet needs its L4 checksum completed by the peer, using
/// `csum_start` / `csum_offset`.
pub(crate) const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

/// `gso_type`: no segmentation — a single, fully formed IP packet follows.
pub(crate) const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
/// `gso_type`: the payload is a TCP-over-IPv4 super-segment to be split into
/// `gso_size`-sized MSS segments by the receiver.
pub(crate) const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
/// `gso_type`: TCP-over-IPv6 super-segment.
pub(crate) const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
/// `gso_type`: UDP segmentation offload (USO / `GSO_UDP_L4`). The payload is
/// several `gso_size`-sized UDP datagrams of one flow coalesced behind a single
/// UDP header, to be split by the receiver. Only handed to us on read when
/// `TUNSETOFFLOAD` requested `TUN_F_USO4` / `TUN_F_USO6`.
pub(crate) const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
/// `gso_type` high bit the kernel ORs onto the base GSO type when the
/// (segmented) packet carries an ECN CE mark. It is NOT a distinct type, so it
/// must be masked off before matching the base type — otherwise an ECN-marked
/// super-packet (`GSO_TCPV4 | ECN` = `0x81`, etc.) fails every arm and is
/// silently dropped.
pub(crate) const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Parsed / buildable `virtio_net_hdr`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    /// A header describing a single, self-contained IP packet: no checksum
    /// offload and no segmentation. The kernel passes such a packet through
    /// verbatim, so the IP/TCP checksums we compute in `wire.rs` are used as-is.
    pub(crate) const NONE: Self = Self {
        flags: 0,
        gso_type: VIRTIO_NET_HDR_GSO_NONE,
        hdr_len: 0,
        gso_size: 0,
        csum_start: 0,
        csum_offset: 0,
    };

    /// Serialise into the fixed 10-byte on-fd representation (host byte order).
    pub(crate) fn encode(&self) -> [u8; VIRTIO_NET_HDR_LEN] {
        let mut bytes = [0u8; VIRTIO_NET_HDR_LEN];
        bytes[0] = self.flags;
        bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
        bytes
    }

    /// Parse the leading 10 bytes of a vnet-prefixed read. Returns `None` if
    /// the buffer is too short to contain a header.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < VIRTIO_NET_HDR_LEN {
            return None;
        }
        Some(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_ne_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_ne_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_ne_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_ne_bytes([bytes[8], bytes[9]]),
        })
    }

    /// Whether this header describes a segmented (GSO) super-packet rather than
    /// a single IP packet. The read loop dispatches on `gso_type` directly (it
    /// must distinguish TCP vs UDP super-packets), so this predicate is only a
    /// test convenience.
    #[cfg(test)]
    pub(crate) fn is_gso(&self) -> bool {
        self.gso_type != VIRTIO_NET_HDR_GSO_NONE
    }
}

#[cfg(test)]
#[path = "tests/vnet.rs"]
mod tests;
