//! WebSocket frame masking utilities
//!
//! Re-exports from simd module with additional utilities.
//! Uses `fastrand` for fast PRNG mask generation (same as tokio-websockets).

pub use crate::simd::{apply_mask, apply_mask_offset};

/// Generate a random mask for WebSocket client frames
///
/// Uses fastrand which is a fast, non-cryptographic PRNG.
/// This is the same approach used by tokio-websockets.
#[inline]
pub fn generate_mask() -> [u8; 4] {
    fastrand::u32(..).to_ne_bytes()
}

/// Alias for generate_mask for backwards compatibility
#[inline]
pub fn generate_mask_fast() -> [u8; 4] {
    generate_mask()
}
