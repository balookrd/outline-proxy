use std::time::Instant;

use crate::constants::{
    SOCKS5_UDP_FRAGMENT_END, SOCKS5_UDP_FRAGMENT_MASK, SOCKS5_UDP_REASSEMBLY_MAX_BYTES,
    SOCKS5_UDP_REASSEMBLY_TIMEOUT,
};
use crate::error::{Result, Socks5Error};
use crate::target::TargetAddr;
use crate::udp::Socks5UdpPacket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledUdpPacket {
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct UdpFragmentReassembler {
    state: Option<UdpFragmentState>,
}

#[derive(Debug)]
struct UdpFragmentState {
    target: TargetAddr,
    fragments: Vec<Vec<u8>>,
    highest_fragment: u8,
    total_bytes: usize,
    deadline: Instant,
}

impl UdpFragmentReassembler {
    pub fn push_fragment(
        &mut self,
        packet: Socks5UdpPacket<'_>,
    ) -> Result<Option<ReassembledUdpPacket>> {
        if packet.fragment == 0 {
            self.state = None;
            return Ok(Some(ReassembledUdpPacket {
                target: packet.target,
                payload: packet.payload.to_vec(),
            }));
        }

        let fragment_number = packet.fragment & SOCKS5_UDP_FRAGMENT_MASK;
        if fragment_number == 0 {
            return Err(Socks5Error::InvalidUdpFragmentZero);
        }
        let is_last = packet.fragment & SOCKS5_UDP_FRAGMENT_END != 0;
        let now = Instant::now();

        if self.state.as_ref().is_some_and(|state| {
            now >= state.deadline
                || packet.target != state.target
                || fragment_number < state.highest_fragment
        }) {
            self.state = None;
        }

        let state = self.state.get_or_insert_with(|| UdpFragmentState {
            target: packet.target.clone(),
            fragments: Vec::new(),
            highest_fragment: 0,
            total_bytes: 0,
            deadline: now + SOCKS5_UDP_REASSEMBLY_TIMEOUT,
        });

        if packet.target != state.target {
            return Err(Socks5Error::FragmentTargetChanged);
        }
        if fragment_number <= state.highest_fragment {
            return Err(Socks5Error::OutOfOrderUdpFragment(fragment_number));
        }

        let projected_total = state.total_bytes.saturating_add(packet.payload.len());
        if projected_total > SOCKS5_UDP_REASSEMBLY_MAX_BYTES {
            self.state = None;
            return Err(Socks5Error::ReassemblyCapExceeded {
                projected: projected_total,
                limit: SOCKS5_UDP_REASSEMBLY_MAX_BYTES,
            });
        }

        state.highest_fragment = fragment_number;
        state.total_bytes = projected_total;
        state.deadline = now + SOCKS5_UDP_REASSEMBLY_TIMEOUT;
        state.fragments.push(packet.payload.to_vec());

        if !is_last {
            return Ok(None);
        }

        let state = self.state.take().expect("state exists when final fragment arrives");
        let mut payload = Vec::with_capacity(state.total_bytes);
        for fragment in state.fragments {
            payload.extend_from_slice(&fragment);
        }

        Ok(Some(ReassembledUdpPacket { target: state.target, payload }))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::udp::parse_udp_request;

    use super::*;

    #[test]
    fn udp_fragment_reassembly_round_trip() {
        let mut reassembler = UdpFragmentReassembler::default();
        let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 53);

        let first = vec![0, 0, 1];
        let second = vec![0, 0, SOCKS5_UDP_FRAGMENT_END | 2];

        let mut packet = first;
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"hel");
        let parsed = parse_udp_request(&packet).unwrap();
        assert!(reassembler.push_fragment(parsed).unwrap().is_none());

        let mut packet = second;
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"lo");
        let parsed = parse_udp_request(&packet).unwrap();
        let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();

        assert_eq!(reassembled.target, target);
        assert_eq!(reassembled.payload, b"hello");
    }

    #[test]
    fn udp_fragment_reassembly_rejects_oversized_sequence() {
        let mut reassembler = UdpFragmentReassembler::default();
        let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let target_wire = target.to_wire_bytes().unwrap();

        let chunk = vec![0u8; 64 * 1024];
        let fragments_to_exceed_cap = SOCKS5_UDP_REASSEMBLY_MAX_BYTES / chunk.len() + 2;

        let mut rejected = false;
        for i in 1..=fragments_to_exceed_cap {
            let mut packet = vec![0, 0, i as u8];
            packet.extend_from_slice(&target_wire);
            packet.extend_from_slice(&chunk);
            let parsed = parse_udp_request(&packet).unwrap();
            match reassembler.push_fragment(parsed) {
                Ok(_) => {}
                Err(_) => {
                    rejected = true;
                    break;
                }
            }
        }
        assert!(rejected, "expected reassembler to bail once byte cap was crossed");

        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(&target_wire);
        packet.extend_from_slice(b"ok");
        let parsed = parse_udp_request(&packet).unwrap();
        let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();
        assert_eq!(reassembled.payload, b"ok");
    }

    #[test]
    fn udp_fragment_reassembly_resets_on_lower_fragment_number() {
        let mut reassembler = UdpFragmentReassembler::default();
        let target = TargetAddr::IpV4(Ipv4Addr::new(8, 8, 4, 4), 53);

        let mut packet = vec![0, 0, 2];
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"stale");
        let parsed = parse_udp_request(&packet).unwrap();
        assert!(reassembler.push_fragment(parsed).unwrap().is_none());

        let mut packet = vec![0, 0, SOCKS5_UDP_FRAGMENT_END | 1];
        packet.extend_from_slice(&target.to_wire_bytes().unwrap());
        packet.extend_from_slice(b"fresh");
        let parsed = parse_udp_request(&packet).unwrap();
        let reassembled = reassembler.push_fragment(parsed).unwrap().unwrap();

        assert_eq!(reassembled.payload, b"fresh");
    }
}
