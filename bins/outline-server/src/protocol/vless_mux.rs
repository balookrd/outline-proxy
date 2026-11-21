//! mux.cool frame codec, shared with the client side via `outline-wire`.

pub use outline_wire::vless_mux::{
    FrameMeta, MAX_FRAME_DATA_SIZE, Network, OPTION_DATA, OPTION_ERROR, ParsedFrame, SessionStatus,
    encode_frame, parse_frame,
};
