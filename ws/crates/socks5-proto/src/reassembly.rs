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
#[path = "tests/reassembly.rs"]
mod tests;
