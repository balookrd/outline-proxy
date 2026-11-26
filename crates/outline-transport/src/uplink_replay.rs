//! Client uplink replay buffer backed by [`outline_wire::replay_ring::ReplayRing`].

use outline_wire::replay_ring::ReplayRing;
pub use outline_wire::replay_ring::{PushError, ReplayError};

pub struct ClientUpstreamRingBuffer(ReplayRing);

impl ClientUpstreamRingBuffer {
    pub fn new(capacity_bytes: usize) -> Self {
        Self(ReplayRing::new(capacity_bytes))
    }

    pub fn capacity_bytes(&self) -> usize {
        self.0.capacity_bytes()
    }

    pub fn total_sent(&self) -> u64 {
        self.0.total_sent()
    }

    pub fn oldest_offset(&self) -> u64 {
        self.0.oldest_offset()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.0.buffered_bytes()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<(), PushError> {
        self.0.push_strict(chunk)
    }

    pub fn replay_from(&self, offset: u64) -> Result<Vec<u8>, ReplayError> {
        self.0.replay_from(offset)
    }
}

#[cfg(test)]
#[path = "tests/uplink_replay.rs"]
mod tests;
