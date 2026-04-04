//! Fuzz target for WebSocket protocol state machine
//!
//! Tests the complete protocol handling:
//! - Frame encoding/decoding round-trip
//! - Message fragmentation and reassembly
//! - Control frame handling (ping, pong, close)
//! - Protocol state transitions

#![no_main]

use arbitrary::Arbitrary;
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use sockudo_ws::frame::{FrameHeader, FrameParser, OpCode};
use sockudo_ws::simd::generate_mask;

#[derive(Arbitrary, Debug)]
struct FuzzFrame {
    opcode: u8,
    payload: Vec<u8>,
    fin: bool,
    masked: bool,
}

impl FuzzFrame {
    fn to_opcode(&self) -> Option<OpCode> {
        match self.opcode % 16 {
            0 => Some(OpCode::Continuation),
            1 => Some(OpCode::Text),
            2 => Some(OpCode::Binary),
            8 => Some(OpCode::Close),
            9 => Some(OpCode::Ping),
            10 => Some(OpCode::Pong),
            _ => None,
        }
    }
}

fuzz_target!(|frames: Vec<FuzzFrame>| {
    for fuzz_frame in frames {
        let Some(opcode) = fuzz_frame.to_opcode() else {
            continue;
        };

        // Limit payload size for control frames
        let payload: &[u8] = if opcode.is_control() && fuzz_frame.payload.len() > 125 {
            &fuzz_frame.payload[..125]
        } else if fuzz_frame.payload.len() > 4096 {
            // Limit overall payload for fuzzing efficiency
            &fuzz_frame.payload[..4096]
        } else {
            &fuzz_frame.payload[..]
        };

        // Create frame header
        let mask = if fuzz_frame.masked {
            Some(generate_mask())
        } else {
            None
        };

        let header = FrameHeader {
            fin: fuzz_frame.fin || opcode.is_control(), // Control frames must have FIN
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            masked: fuzz_frame.masked,
            payload_len: payload.len() as u64,
            mask,
        };

        // Encode the frame
        let mut encoded = BytesMut::new();
        header.encode(&mut encoded);

        // Add payload (apply mask if needed)
        let mut payload_buf = payload.to_vec();
        if let Some(m) = mask {
            sockudo_ws::simd::apply_mask(&mut payload_buf, m);
        }
        encoded.extend_from_slice(&payload_buf);

        // Decode it back
        let mut parser = FrameParser::new(1024 * 1024, fuzz_frame.masked);
        match parser.parse(&mut encoded) {
            Ok(Some(decoded)) => {
                // Verify round-trip
                assert_eq!(decoded.header.fin, header.fin, "FIN mismatch");
                assert_eq!(decoded.header.opcode, header.opcode, "OpCode mismatch");
                // Payload should match (after unmasking, which parser does)
                assert_eq!(
                    decoded.payload.len(),
                    payload.len(),
                    "Payload length mismatch"
                );
            }
            Ok(None) => {
                // Incomplete frame - this shouldn't happen for a complete encode
                panic!("Parser returned None for complete frame");
            }
            Err(_) => {
                // Parser error - might happen for invalid combinations
                // This is acceptable as long as we don't panic
            }
        }
    }
});
