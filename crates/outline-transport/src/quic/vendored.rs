//! Gate for the patched `quinn-proto` API (see PATCHES.md). Production code reaches the
//! patch only through this module, so a rebase of the vendored crate touches one file.

/// Advertise `advertised` bytes of per-stream credit in the transport parameters while
/// `TransportConfig::stream_receive_window` stays the window granted when the application first
/// polls a receive stream.
pub(crate) fn set_advertised_stream_receive_window(
    transport: &mut quinn::TransportConfig,
    advertised: u32,
) {
    transport.initial_stream_receive_window(Some(quinn::VarInt::from_u32(advertised)));
}
