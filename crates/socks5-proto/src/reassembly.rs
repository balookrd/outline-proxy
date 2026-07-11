use std::borrow::Cow;
use std::time::Instant;

use crate::constants::{
    SOCKS5_UDP_FRAGMENT_END, SOCKS5_UDP_FRAGMENT_MASK, SOCKS5_UDP_REASSEMBLY_MAX_BYTES,
    SOCKS5_UDP_REASSEMBLY_TIMEOUT,
};
use crate::error::{Result, Socks5Error};
use crate::target::TargetAddr;
use crate::udp::Socks5UdpPacket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledUdpPacket<'a> {
    pub target: TargetAddr,
    /// Shadowsocks UDP body `addr_wire || data`. Borrowed straight from the
    /// input datagram for a non-fragmented packet (the common case, zero-copy);
    /// owned only when several fragments had to be concatenated.
    pub payload: Cow<'a, [u8]>,
    /// Length of the leading address in `payload`; `payload[addr_len..]` is the
    /// datagram data used by the policy-direct path.
    pub addr_len: usize,
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
    pub fn push_fragment<'a>(
        &mut self,
        packet: Socks5UdpPacket<'a>,
    ) -> Result<Option<ReassembledUdpPacket<'a>>> {
        if packet.fragment == 0 {
            self.state = None;
            // Non-fragmented: the datagram's `addr_wire || data` body is already
            // contiguous, so borrow it — no copy, no address re-serialisation.
            let addr_len = packet.body.len() - packet.payload.len();
            return Ok(Some(ReassembledUdpPacket {
                target: packet.target,
                payload: Cow::Borrowed(packet.body),
                addr_len,
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
        // Fragmented: concatenate `addr_wire || data0 || data1 || …` once so the
        // reassembled body matches the non-fragmented borrowed shape.
        let addr_wire = state.target.to_wire_bytes()?;
        let addr_len = addr_wire.len();
        let mut payload = Vec::with_capacity(addr_len + state.total_bytes);
        payload.extend_from_slice(&addr_wire);
        for fragment in state.fragments {
            payload.extend_from_slice(&fragment);
        }

        Ok(Some(ReassembledUdpPacket {
            target: state.target,
            payload: Cow::Owned(payload),
            addr_len,
        }))
    }
}

#[cfg(test)]
#[path = "tests/reassembly.rs"]
mod tests;
