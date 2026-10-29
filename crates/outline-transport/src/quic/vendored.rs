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

/// Transport-parameter knobs from the patched quinn-proto that shape the Initial like a
/// browser. See `tp_profile` for the measured values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BrowserTpOptions {
    pub(crate) advertise_min_ack_delay: bool,
    pub(crate) grease_parameter: bool,
    pub(crate) advertise_idle_timeout: bool,
    pub(crate) advertise_max_udp_payload_size: bool,
    /// Exact `max_datagram_frame_size`; `Some` also enables datagram receive.
    pub(crate) datagram_frame_size: Option<u32>,
    pub(crate) version_information: bool,
    pub(crate) extra_parameters: &'static [(u64, &'static [u8])],
}

pub(crate) fn apply_browser_tp_options(
    transport: &mut quinn::TransportConfig,
    opts: &BrowserTpOptions,
) {
    transport
        .advertise_min_ack_delay(opts.advertise_min_ack_delay)
        .send_grease_transport_parameter(opts.grease_parameter)
        .advertise_max_idle_timeout(opts.advertise_idle_timeout)
        .advertise_max_udp_payload_size(opts.advertise_max_udp_payload_size)
        .send_version_information(opts.version_information)
        .extra_transport_parameters(
            opts.extra_parameters
                .iter()
                .map(|(id, value)| {
                    (quinn::VarInt::from_u64(*id).expect("TP id fits a varint"), value.to_vec())
                })
                .collect(),
        );
    match opts.datagram_frame_size {
        Some(size) => {
            transport
                .datagram_receive_buffer_size(Some(size as usize))
                .advertised_max_datagram_frame_size(Some(quinn::VarInt::from_u32(size)));
        },
        None => {
            transport.datagram_receive_buffer_size(None);
        },
    }
}
