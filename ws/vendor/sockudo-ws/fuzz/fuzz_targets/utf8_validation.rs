//! Fuzz target for UTF-8 validation
//!
//! Tests the SIMD-accelerated UTF-8 validation:
//! - Correct acceptance of valid UTF-8
//! - Correct rejection of invalid UTF-8
//! - Proper handling of incomplete sequences
//! - Consistency with std::str::from_utf8

#![no_main]

use libfuzzer_sys::fuzz_target;
use sockudo_ws::utf8::{validate_utf8, validate_utf8_incomplete};

fuzz_target!(|data: &[u8]| {
    // Our validation should match std's validation
    let our_result = validate_utf8(data);
    let std_result = std::str::from_utf8(data).is_ok();
    assert_eq!(
        our_result, std_result,
        "UTF-8 validation mismatch: our={}, std={}, data={:?}",
        our_result, std_result, data
    );

    // Test incomplete validation
    let (valid, incomplete_bytes) = validate_utf8_incomplete(data);

    // If std says it's valid, our incomplete check should also say valid with 0 incomplete
    if std_result {
        assert!(
            valid,
            "validate_utf8_incomplete returned invalid for valid UTF-8"
        );
        assert_eq!(
            incomplete_bytes, 0,
            "validate_utf8_incomplete returned incomplete bytes for complete valid UTF-8"
        );
    }

    // If we say it's valid with incomplete bytes, the complete prefix should be valid UTF-8
    if valid && incomplete_bytes > 0 && data.len() >= incomplete_bytes {
        let prefix = &data[..data.len() - incomplete_bytes];
        assert!(
            std::str::from_utf8(prefix).is_ok(),
            "Prefix should be valid UTF-8 when incomplete bytes are reported"
        );
    }
});
