//! Tests for the mux TCP sub-connection reader's downlink sizing.

use bytes::BytesMut;
use outline_wire::padding::PaddingScheme;

use super::*;
use crate::server::transport::carrier_padding::{H2_DATA_PAYLOAD_MAX, H2_WS_HEADER_LEN};

/// Off h2 the reader keeps its whole relay buffer as the read limit.
#[test]
fn read_limit_is_the_buffer_off_h2() {
    for protocol in [Protocol::Http1, Protocol::XhttpH1, Protocol::Http3, Protocol::XhttpH3] {
        for padding in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            assert_eq!(read_limit(16 * 1024, protocol, padding), 16 * 1024, "{protocol:?}");
        }
    }
}

/// On h2 a full mux data frame at the limit, padded at the scheme's largest
/// pad and behind its WS header, is exactly one h2 DATA frame of one record.
#[test]
fn a_full_data_frame_at_the_h2_limit_fits_one_data_frame() {
    for protocol in [Protocol::Http2, Protocol::XhttpH2] {
        for padding in [PaddingScheme::disabled(), PaddingScheme::new(0, 256)] {
            let limit = read_limit(16 * 1024, protocol, padding);
            assert!(limit < 16 * 1024, "{protocol:?} {padding:?}");
            let mut frame = BytesMut::new();
            encode_frame(
                &mut frame,
                0x1234,
                SessionStatus::Keep,
                OPTION_DATA,
                None,
                None,
                Some(&vec![0u8; limit]),
            )
            .expect("a capped data frame encodes");
            assert_eq!(frame.len(), limit + MUX_DATA_FRAME_OVERHEAD);
            let pad = if padding.is_enabled() {
                4 + usize::from(padding.max_pad())
            } else {
                0
            };
            assert_eq!(
                frame.len() + pad + H2_WS_HEADER_LEN,
                H2_DATA_PAYLOAD_MAX,
                "{protocol:?} {padding:?}"
            );
        }
    }
}
