//! Browser-like layout of the client's ClientHello in CRYPTO frames across its Initial
//! packets (outline-proxy patch, see [`InitialCryptoLayout`]).
//!
//! Upstream quinn fills the first Initial with one CRYPTO frame and puts the rest of the
//! hello in the next one. Chrome and Firefox both split the hello evenly over their
//! Initials, the first one carrying the head and the tail of the hello and the next ones
//! the middle; Chrome then also scatters each packet's frames ("chaos protection").
//!
//! The planned frames are queued in `pending.crypto` in packet order, one frame per
//! range, so quinn still sees pending data and resends lost frames as usual. `hello_plan`
//! records the offsets each planned packet starts with; a packet that does not find
//! exactly those frames at the front of the queue, or has no room for them, drops the
//! plan and the remaining frames go out through the upstream loop.

use std::ops::Range;

use bytes::{BufMut, Bytes, BytesMut};
use rand::{Rng, RngExt};
use tracing::trace;

use super::{Connection, SentFrames, SpaceId};
use crate::{
    VarInt,
    coding::BufMutExt,
    config::InitialCryptoLayout,
    frame::{self, FrameType},
};

/// Room kept per packet for the frames chaos protection adds: up to this many extra
/// CRYPTO frames and PINGs per packet, as QUICHE does.
const CHAOS_MAX_ADDED_CRYPTO: usize = 10;
const CHAOS_MAX_PINGS: usize = 10;
/// Largest CRYPTO frame header: type, a 4-byte offset, a 2-byte length.
const CRYPTO_HEADER_MAX: usize = 1 + 4 + 2;
const CHAOS_RESERVE: usize = CHAOS_MAX_ADDED_CRYPTO * CRYPTO_HEADER_MAX + CHAOS_MAX_PINGS;
/// Chrome's head cut, in bytes of the hello; measured 55 and 79.
const CHAOS_HEAD: Range<usize> = 40..101;
/// Below this much hello data per packet the layout is not worth it.
const MIN_SHARE: usize = 256;

/// One item of a packet laid out by [`scatter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Piece {
    Crypto(Range<usize>),
    Ping,
    Padding(usize),
}

/// Whether `data` is exactly one complete TLS ClientHello message.
pub(super) fn is_client_hello(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == 1
        && u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize + 4 == data.len()
}

/// Byte range of the SNI host name inside a ClientHello message.
pub(super) fn sni_range(hello: &[u8]) -> Option<Range<usize>> {
    let u16_at = |p: usize| -> Option<usize> {
        Some(u16::from_be_bytes([*hello.get(p)?, *hello.get(p + 1)?]) as usize)
    };
    // type(1) length(3) legacy_version(2) random(32)
    let mut p = 4 + 2 + 32;
    p += 1 + *hello.get(p)? as usize; // session id
    p += 2 + u16_at(p)?; // cipher suites
    p += 1 + *hello.get(p)? as usize; // compression methods
    let end = p + 2 + u16_at(p)?;
    p += 2;
    if end > hello.len() {
        return None;
    }
    while p + 4 <= end {
        let (ty, len) = (u16_at(p)?, u16_at(p + 2)?);
        let body = p + 4..p + 4 + len;
        if body.end > end {
            return None;
        }
        if ty == 0 {
            // server_name_list length(2), name_type(1), host_name length(2), host_name
            let start = body.start + 5;
            let name = start..start + u16_at(body.start + 3)?;
            return (name.end <= body.end && !name.is_empty()).then_some(name);
        }
        p = body.end;
    }
    None
}

/// Size of a CRYPTO frame carrying `range` of the hello.
pub(super) fn crypto_frame_len(range: &Range<usize>) -> usize {
    let size = |v: usize| VarInt::from_u64(v as u64).map_or(8, VarInt::size);
    1 + size(range.start) + size(range.len()) + range.len()
}

/// The CRYPTO ranges of each Initial for a hello of `len` bytes when a packet has `room`
/// bytes for frames. `None` when the layout does not apply.
pub(super) fn plan(
    layout: InitialCryptoLayout,
    len: usize,
    sni: Option<Range<usize>>,
    room: usize,
    rng: &mut impl Rng,
) -> Option<Vec<Vec<Range<usize>>>> {
    let reserve = 2 * CRYPTO_HEADER_MAX
        + match layout {
            InitialCryptoLayout::Contiguous => return None,
            InitialCryptoLayout::Chaos => CHAOS_RESERVE,
            InitialCryptoLayout::SniSlice => 0,
        };
    let usable = room.checked_sub(reserve).filter(|&u| u >= MIN_SHARE)?;
    let head = match layout {
        InitialCryptoLayout::SniSlice => sni.map(|name| name.start + name.len() / 2)?,
        _ => rng.random_range(CHAOS_HEAD),
    };
    let packets = len.div_ceil(usable);
    if packets == 1 {
        return (0 < head && head < len).then(|| vec![vec![head..len, 0..head]]);
    }
    let share = len.div_ceil(packets);
    if head == 0 || head >= len {
        return None;
    }
    // The first packet carries `share` bytes from both sides of the cut, the part
    // after it first, and leaves one contiguous range for the next packets (neqo).
    let (first, rest) = if head < share {
        // The head fits: all of it, plus the end of the part after the cut.
        let tail = len - (share - head);
        (vec![tail..len, 0..head], head..tail)
    } else if len - head < share {
        // A late SNI: all of the part after the cut, plus the end of the head.
        let start = len - share;
        (vec![head..len, start..head], 0..start)
    } else {
        return None;
    };
    let mut out = vec![first];
    let piece = rest.len().div_ceil(packets - 1);
    let mut start = rest.start;
    while start < rest.end {
        let end = (start + piece).min(rest.end);
        out.push(vec![start..end]);
        start = end;
    }
    Some(out)
}

/// Chrome's chaos protection for one packet's `ranges`, with `spare` bytes to fill
/// before the packet's padding target: extra CRYPTO splits, PINGs, a shuffled order and
/// PADDING spread before the frames. Padding left over goes at the end of the packet.
pub(super) fn scatter(
    ranges: Vec<Range<usize>>,
    mut spare: usize,
    rng: &mut impl Rng,
) -> Vec<Piece> {
    let mut crypto = ranges;
    for _ in 0..rng.random_range(0..=CHAOS_MAX_ADDED_CRYPTO) {
        if spare < CRYPTO_HEADER_MAX {
            break;
        }
        let i = rng.random_range(0..crypto.len());
        let r = crypto[i].clone();
        if r.len() < 2 {
            continue;
        }
        let cut = rng.random_range(r.start + 1..r.end);
        let (a, b) = (r.start..cut, cut..r.end);
        let grown = crypto_frame_len(&a) + crypto_frame_len(&b) - crypto_frame_len(&r);
        spare -= grown;
        crypto[i] = a;
        crypto.insert(i + 1, b);
    }
    let pings = rng.random_range(0..=CHAOS_MAX_PINGS).min(spare);
    spare -= pings;
    let mut items: Vec<Piece> = crypto.into_iter().map(Piece::Crypto).collect();
    items.extend((0..pings).map(|_| Piece::Ping));
    // Fisher-Yates
    for i in (1..items.len()).rev() {
        items.swap(i, rng.random_range(0..=i));
    }
    let mut out = Vec::with_capacity(items.len() * 2);
    for item in items {
        let pad = rng.random_range(0..=spare);
        if pad > 0 {
            out.push(Piece::Padding(pad));
            spare -= pad;
        }
        out.push(item);
    }
    out
}

impl Connection {
    /// Writes this Initial packet's CRYPTO frames when the hello is laid out like a
    /// browser's. `pad_target` is the buffer position the packet is padded to. Returns
    /// whether it wrote the packet's frames; the upstream loop must then add no more
    /// CRYPTO, which belongs to the next planned packets. Writes nothing when no plan
    /// applies.
    pub(super) fn populate_initial_hello(
        &mut self,
        buf: &mut Vec<u8>,
        max_size: usize,
        pad_target: usize,
        sent: &mut SentFrames,
    ) -> bool {
        let layout = self.config.initial_crypto_layout;
        if layout == InitialCryptoLayout::Contiguous || !self.side.is_client() {
            return false;
        }
        let limit = pad_target.min(max_size);
        if self.hello_plan.is_empty() {
            self.plan_initial_hello(layout, limit.saturating_sub(buf.len()));
        }
        let Some(offsets) = self.hello_plan.pop_front() else {
            return false;
        };
        let pending = &mut self.spaces[SpaceId::Initial].pending.crypto;
        let matches = pending.len() >= offsets.len()
            && pending.iter().zip(&offsets).all(|(f, &o)| f.offset == o);
        let frames: Vec<frame::Crypto> = if matches {
            pending.drain(..offsets.len()).collect()
        } else {
            Vec::new()
        };
        let size: usize = frames
            .iter()
            .map(|f| crypto_frame_len(&(f.offset as usize..f.offset as usize + f.data.len())))
            .sum();
        if !matches || buf.len() + size > limit {
            for frame in frames.into_iter().rev() {
                pending.push_front(frame);
            }
            self.hello_plan.clear();
            return false;
        }

        let ranges = |f: &frame::Crypto| f.offset as usize..f.offset as usize + f.data.len();
        let pieces = match layout {
            InitialCryptoLayout::Chaos => {
                // Ranges stay absolute; `slice` below maps them back into their frame.
                scatter(
                    frames.iter().map(ranges).collect(),
                    limit - buf.len() - size,
                    &mut self.rng,
                )
            },
            _ => frames.iter().map(|f| Piece::Crypto(ranges(f))).collect(),
        };
        let laid_out: usize = pieces
            .iter()
            .map(|piece| match piece {
                Piece::Crypto(range) => crypto_frame_len(range),
                Piece::Ping => 1,
                Piece::Padding(n) => *n,
            })
            .sum();
        // Never write past the target: the padding below would cut written frames off.
        let fits = buf.len() + laid_out <= limit;
        debug_assert!(fits, "laid-out hello overflows the packet");
        if !fits {
            for frame in frames.into_iter().rev() {
                pending.push_front(frame);
            }
            self.hello_plan.clear();
            return false;
        }
        let slice = |range: &Range<usize>| -> frame::Crypto {
            let f = frames
                .iter()
                .find(|f| ranges(f).start <= range.start && range.end <= ranges(f).end)
                .expect("a scattered range stays inside its frame");
            let at = range.start - f.offset as usize;
            frame::Crypto {
                offset: range.start as u64,
                data: f.data.slice(at..at + range.len()),
            }
        };
        for piece in pieces {
            match piece {
                Piece::Crypto(range) => {
                    let frame = slice(&range);
                    trace!("CRYPTO: off {} len {} (laid out)", frame.offset, frame.data.len());
                    frame.encode(buf);
                    self.stats.frame_tx.crypto += 1;
                    sent.retransmits.get_or_create().crypto.push_back(frame);
                },
                Piece::Ping => {
                    buf.write(FrameType::PING);
                    sent.non_retransmits = true;
                    self.stats.frame_tx.ping += 1;
                },
                Piece::Padding(n) => buf.put_bytes(0, n),
            }
        }
        // Pad the packet out to its target, as the browsers do, so no further packet is
        // coalesced into the rest of the datagram.
        buf.resize(limit, 0);
        true
    }

    /// Replaces a complete pending hello with the frames of a fresh plan.
    fn plan_initial_hello(&mut self, layout: InitialCryptoLayout, room: usize) {
        let pending = &mut self.spaces[SpaceId::Initial].pending.crypto;
        if pending.is_empty() {
            return;
        }
        let mut sorted: Vec<&frame::Crypto> = pending.iter().collect();
        sorted.sort_by_key(|f| f.offset);
        let mut next = 0;
        for f in &sorted {
            if f.offset != next {
                return;
            }
            next += f.data.len() as u64;
        }
        let hello: Bytes = if sorted.len() == 1 {
            sorted[0].data.clone()
        } else {
            let mut all = BytesMut::with_capacity(next as usize);
            for f in &sorted {
                all.extend_from_slice(&f.data);
            }
            all.freeze()
        };
        if !is_client_hello(&hello) {
            return;
        }
        let Some(packets) = plan(layout, hello.len(), sni_range(&hello), room, &mut self.rng)
        else {
            return;
        };
        pending.clear();
        for packet in packets {
            self.hello_plan
                .push_back(packet.iter().map(|r| r.start as u64).collect());
            for r in packet {
                pending.push_back(frame::Crypto {
                    offset: r.start as u64,
                    data: hello.slice(r),
                });
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/initial_crypto.rs"]
mod tests;
