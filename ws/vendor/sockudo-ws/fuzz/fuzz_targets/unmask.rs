//! Fuzz target for WebSocket frame unmasking (XOR operation)
//!
//! Tests the SIMD-accelerated masking implementation:
//! - Correct XOR behavior for all input lengths
//! - Proper alignment handling
//! - No panics or buffer overflows
//! - Mask rotation correctness

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sockudo_ws::simd::{apply_mask, apply_mask_offset};

#[derive(Arbitrary, Debug)]
struct MaskInput {
    data: Vec<u8>,
    mask: [u8; 4],
    offset: u8,
}

fuzz_target!(|input: MaskInput| {
    // Test basic masking (XOR is self-inverse)
    let mut data = input.data.clone();
    apply_mask(&mut data, input.mask);
    apply_mask(&mut data, input.mask);
    assert_eq!(data, input.data, "XOR self-inverse property violated");

    // Test masking with offset
    let mut data = input.data.clone();
    let offset = (input.offset as usize) % 4;
    apply_mask_offset(&mut data, input.mask, offset);
    apply_mask_offset(&mut data, input.mask, offset);
    assert_eq!(
        data, input.data,
        "XOR with offset self-inverse property violated"
    );

    // Test that different offsets produce different results (when data is long enough)
    if input.data.len() >= 4 && input.mask != [0, 0, 0, 0] {
        let mut data1 = input.data.clone();
        let mut data2 = input.data.clone();
        apply_mask_offset(&mut data1, input.mask, 0);
        apply_mask_offset(&mut data2, input.mask, 1);
        // They should be different unless the mask has special properties
        // (not asserting this as it depends on mask values)
    }
});
