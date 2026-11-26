//! Bounded byte-offset-addressed FIFO replay ring shared by the client uplink
//! and server downlink session-resumption buffers.

use std::collections::VecDeque;

/// Failure modes for [`ReplayRing::push_strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    OversizedSingleChunk { chunk_len: usize, capacity_bytes: usize },
}

/// Failure modes for [`ReplayRing::replay_from`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    OffsetEvicted { requested: u64, oldest_available: u64 },
    OffsetAhead { requested: u64, total_sent: u64 },
}

#[derive(Debug)]
struct Entry {
    offset: u64,
    payload: Vec<u8>,
}

fn reusable(buffer: Vec<u8>, chunk_len: usize) -> Option<Vec<u8>> {
    (buffer.capacity() <= chunk_len.saturating_mul(2)).then_some(buffer)
}

fn store(recycled: Option<Vec<u8>>, chunk: &[u8]) -> Vec<u8> {
    match recycled {
        Some(mut buffer) => {
            buffer.clear();
            buffer.extend_from_slice(chunk);
            buffer
        },
        None => chunk.to_vec(),
    }
}

/// Bounded FIFO ring of byte chunks indexed by absolute stream offset.
#[derive(Debug)]
pub struct ReplayRing {
    capacity_bytes: usize,
    entries: VecDeque<Entry>,
    current_bytes: usize,
    total_sent: u64,
}

impl ReplayRing {
    pub fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            entries: VecDeque::new(),
            current_bytes: 0,
            total_sent: 0,
        }
    }

    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    pub fn oldest_offset(&self) -> u64 {
        match self.entries.front() {
            Some(entry) => entry.offset,
            None => self.total_sent,
        }
    }

    pub fn buffered_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Strict FIFO push (client uplink): rejects a single chunk larger than
    /// `capacity_bytes` without mutating state.
    pub fn push_strict(&mut self, chunk: &[u8]) -> Result<(), PushError> {
        if chunk.is_empty() {
            return Ok(());
        }
        if chunk.len() > self.capacity_bytes {
            return Err(PushError::OversizedSingleChunk {
                chunk_len: chunk.len(),
                capacity_bytes: self.capacity_bytes,
            });
        }
        self.push_fitting(chunk);
        Ok(())
    }

    /// Infallible FIFO push (server downlink): retains at most the trailing
    /// `capacity_bytes` of an oversized chunk while advancing `total_sent` by
    /// the full `chunk.len()`.
    pub fn push_truncating(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        if self.capacity_bytes == 0 {
            self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
            return;
        }
        if chunk.len() >= self.capacity_bytes {
            self.entries.clear();
            self.current_bytes = 0;
            let drop_prefix = chunk.len() - self.capacity_bytes;
            let kept_offset = self.total_sent.saturating_add(drop_prefix as u64);
            let kept_payload = chunk[drop_prefix..].to_vec();
            let kept_len = kept_payload.len();
            self.entries.push_back(Entry {
                offset: kept_offset,
                payload: kept_payload,
            });
            self.current_bytes = kept_len;
            self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
            return;
        }
        self.push_fitting(chunk);
    }

    fn push_fitting(&mut self, chunk: &[u8]) {
        let mut recycled: Option<Vec<u8>> = None;
        while self.current_bytes + chunk.len() > self.capacity_bytes {
            let evicted = self
                .entries
                .pop_front()
                .expect("loop condition implies entries is non-empty");
            self.current_bytes = self.current_bytes.saturating_sub(evicted.payload.len());
            if let Some(buffer) = reusable(evicted.payload, chunk.len()) {
                recycled = Some(buffer);
            }
        }
        let offset = self.total_sent;
        self.entries
            .push_back(Entry { offset, payload: store(recycled, chunk) });
        self.current_bytes += chunk.len();
        self.total_sent = self.total_sent.saturating_add(chunk.len() as u64);
    }

    /// Returns the contiguous suffix `[offset, total_sent())` as a fresh `Vec<u8>`.
    pub fn replay_from(&self, offset: u64) -> Result<Vec<u8>, ReplayError> {
        if offset > self.total_sent {
            return Err(ReplayError::OffsetAhead {
                requested: offset,
                total_sent: self.total_sent,
            });
        }
        if offset == self.total_sent {
            return Ok(Vec::new());
        }
        let oldest = self.oldest_offset();
        if offset < oldest {
            return Err(ReplayError::OffsetEvicted {
                requested: offset,
                oldest_available: oldest,
            });
        }
        let bytes_to_replay = (self.total_sent - offset) as usize;
        let mut out = Vec::with_capacity(bytes_to_replay);
        for entry in &self.entries {
            let entry_end = entry.offset + entry.payload.len() as u64;
            if entry_end <= offset {
                continue;
            }
            if entry.offset >= offset {
                out.extend_from_slice(&entry.payload);
            } else {
                let split = (offset - entry.offset) as usize;
                out.extend_from_slice(&entry.payload[split..]);
            }
        }
        debug_assert_eq!(out.len(), bytes_to_replay);
        Ok(out)
    }
}

#[cfg(test)]
#[path = "tests/replay_ring.rs"]
mod tests;
