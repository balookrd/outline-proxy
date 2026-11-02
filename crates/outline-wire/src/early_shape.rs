//! Early-session shaping: plans how the first messages of a padded TCP session
//! are cut into browser-sized pieces, so an observer does not see one record the
//! size of the tunnelled TLS ClientHello followed, one RTT later, by one record
//! the size of the server's certificate flight (the TLS-in-TLS signature).
//!
//! Pure planning, like [`crate::padding`]: no RNG and no clock here. The caller
//! passes `draw(lo, hi)`, a uniform integer in `lo..=hi`. Sizes are real payload
//! bytes; each piece still gets the ordinary per-frame padding when sent.

/// Messages the window covers, drawn per session.
const WINDOW_MSGS: (usize, usize) = (6, 10);
/// Payload bytes the window covers, drawn per session.
const WINDOW_BYTES: (usize, usize) = (16 * 1024, 24 * 1024);

/// Client→server: messages longer than this are cut into HEADERS-sized pieces.
const C2S_SPLIT_ABOVE: usize = 900;
const C2S_PIECE: (usize, usize) = (300, 850);
/// Server→client: messages longer than this are cut into response-sized pieces.
const S2C_SPLIT_ABOVE: usize = 1500;
const S2C_PIECE: (usize, usize) = (600, 2800);

/// Lead-in covers before the client's first big message: Chrome sends a few
/// short records after its handshake before HEADERS.
const COVER_COUNT: (usize, usize) = (1, 2);
const COVER_PAD: (usize, usize) = (40, 100);

/// Which way the shaped session half flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeDirection {
    ClientToServer,
    ServerToClient,
}

/// What to send for one message: `covers` pad-only frames first (their pad
/// sizes), then `pieces` (lengths, summing to the message length) as separate
/// messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapePlan {
    pub covers: Vec<usize>,
    pub pieces: Vec<usize>,
}

#[derive(Debug)]
pub struct EarlyShaper {
    direction: ShapeDirection,
    msgs_left: usize,
    bytes_left: usize,
    covers_pending: bool,
}

impl EarlyShaper {
    /// Opens a shaping window with per-session random limits drawn via `draw`.
    pub fn new(direction: ShapeDirection, draw: &mut dyn FnMut(usize, usize) -> usize) -> Self {
        let msgs_left = draw(WINDOW_MSGS.0, WINDOW_MSGS.1);
        let bytes_left = draw(WINDOW_BYTES.0, WINDOW_BYTES.1);
        let covers_pending = direction == ShapeDirection::ClientToServer && draw(0, 1) == 1;
        Self {
            direction,
            msgs_left,
            bytes_left,
            covers_pending,
        }
    }

    /// Whether the window is still open.
    pub fn is_active(&self) -> bool {
        self.msgs_left > 0 && self.bytes_left > 0
    }

    /// Plans one message of `len` bytes. Empty messages pass through without
    /// using a window slot; messages above the split threshold are cut into at
    /// least two pieces while the window is open.
    pub fn plan(&mut self, len: usize, draw: &mut dyn FnMut(usize, usize) -> usize) -> ShapePlan {
        if len == 0 || !self.is_active() {
            return ShapePlan { covers: Vec::new(), pieces: vec![len] };
        }
        self.msgs_left -= 1;
        let (split_above, piece) = match self.direction {
            ShapeDirection::ClientToServer => (C2S_SPLIT_ABOVE, C2S_PIECE),
            ShapeDirection::ServerToClient => (S2C_SPLIT_ABOVE, S2C_PIECE),
        };
        let shaped = len.min(self.bytes_left);
        self.bytes_left -= shaped;
        // Too small to split meaningfully (message or remaining budget).
        if len <= split_above || shaped <= split_above {
            return ShapePlan { covers: Vec::new(), pieces: vec![len] };
        }
        let mut covers = Vec::new();
        if self.covers_pending {
            self.covers_pending = false;
            for _ in 0..draw(COVER_COUNT.0, COVER_COUNT.1).clamp(COVER_COUNT.0, COVER_COUNT.1) {
                covers.push(draw(COVER_PAD.0, COVER_PAD.1).clamp(COVER_PAD.0, COVER_PAD.1));
            }
        }
        let mut pieces = Vec::new();
        let mut left = shaped;
        loop {
            // Keep at least `piece.0` for the next piece so the split never
            // degenerates to a single piece.
            debug_assert!(left >= 2 * piece.0);
            let hi = piece.1.min(left - piece.0);
            let p = draw(piece.0, hi).clamp(piece.0, hi);
            pieces.push(p);
            left -= p;
            if left <= piece.1 {
                break;
            }
        }
        if left < piece.0 {
            *pieces.last_mut().expect("at least one piece") += left;
        } else {
            pieces.push(left);
        }
        if len > shaped {
            pieces.push(len - shaped);
        }
        ShapePlan { covers, pieces }
    }
}

#[cfg(test)]
#[path = "tests/early_shape.rs"]
mod tests;
