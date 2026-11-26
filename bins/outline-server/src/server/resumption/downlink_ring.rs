//! Server downlink replay buffer backed by [`outline_wire::replay_ring::ReplayRing`].

use outline_wire::replay_ring::{ReplayError, ReplayRing};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplayOutcome {
    Available(Vec<u8>),
    Truncated,
    OffsetAhead,
}

pub(crate) struct DownlinkRing(ReplayRing);

impl DownlinkRing {
    pub(crate) fn new(capacity_bytes: usize) -> Self {
        Self(ReplayRing::new(capacity_bytes))
    }

    #[allow(dead_code)]
    pub(crate) fn capacity_bytes(&self) -> usize {
        self.0.capacity_bytes()
    }

    pub(crate) fn total_sent(&self) -> u64 {
        self.0.total_sent()
    }

    pub(crate) fn oldest_offset(&self) -> u64 {
        self.0.oldest_offset()
    }

    pub(crate) fn buffered_bytes(&self) -> usize {
        self.0.buffered_bytes()
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) {
        self.0.push_truncating(chunk);
    }

    pub(crate) fn replay_from(&self, offset: u64) -> ReplayOutcome {
        match self.0.replay_from(offset) {
            Ok(bytes) => ReplayOutcome::Available(bytes),
            Err(ReplayError::OffsetEvicted { .. }) => ReplayOutcome::Truncated,
            Err(ReplayError::OffsetAhead { .. }) => ReplayOutcome::OffsetAhead,
        }
    }
}

#[cfg(test)]
#[path = "tests/downlink_ring.rs"]
mod tests;
