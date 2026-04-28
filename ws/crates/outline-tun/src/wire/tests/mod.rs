use super::{checksum16, checksum16_parts};

#[test]
fn checksum16_parts_matches_flat_buffer_for_odd_boundaries() {
    let parts = [b"\x12".as_slice(), b"\x34\x56".as_slice(), b"\x78\x9a\xbc".as_slice()];
    let flat = b"\x12\x34\x56\x78\x9a\xbc";
    assert_eq!(checksum16_parts(&parts), checksum16(flat));
}
