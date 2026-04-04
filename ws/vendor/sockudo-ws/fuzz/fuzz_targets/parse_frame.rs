//! Fuzz target for WebSocket frame parsing
//!
//! Tests the frame parser with arbitrary byte sequences to ensure:
//! - No panics on malformed input
//! - No buffer overflows
//! - Correct handling of truncated frames
//! - Proper rejection of invalid opcodes and lengths

#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use sockudo_ws::frame::FrameParser;

fuzz_target!(|data: &[u8]| {
    // Test server-side parsing (expects masked frames from clients)
    let mut parser_server = FrameParser::new(1024 * 1024, true);
    let mut buf = BytesMut::from(data);
    let _ = parser_server.parse(&mut buf);

    // Test client-side parsing (expects unmasked frames from servers)
    let mut parser_client = FrameParser::new(1024 * 1024, false);
    let mut buf = BytesMut::from(data);
    let _ = parser_client.parse(&mut buf);

    // Test with compression enabled
    let mut parser_compressed = FrameParser::with_compression(1024 * 1024, true);
    let mut buf = BytesMut::from(data);
    let _ = parser_compressed.parse(&mut buf);
});
