//! Gate for the patched `quinn-proto` API (see PATCHES.md). Production code reaches the
//! patch only through this module, so a rebase of the vendored crate touches one file.

pub(crate) use quinn_proto::VersionSlot;

/// Advertise `advertised` bytes of per-stream credit in the transport parameters while
/// `TransportConfig::stream_receive_window` stays the window granted when the application first
/// polls a receive stream.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "profiles advertise per-direction windows; tests use the uniform form"
    )
)]
pub(crate) fn set_advertised_stream_receive_window(
    transport: &mut quinn::TransportConfig,
    advertised: u32,
) {
    transport.initial_stream_receive_window(Some(quinn::VarInt::from_u32(advertised)));
}

/// Advertise per-direction stream credit (`initial_max_stream_data_bidi_local`,
/// `_bidi_remote`, `_uni`); `TransportConfig::stream_receive_window` stays the window
/// granted when the application first polls a receive stream.
pub(crate) fn set_advertised_stream_receive_windows(
    transport: &mut quinn::TransportConfig,
    bidi_local: u32,
    bidi_remote: u32,
    uni: u32,
) {
    transport.initial_stream_receive_windows(Some(quinn_proto::StreamReceiveWindows {
        bidi_local: quinn::VarInt::from_u32(bidi_local),
        bidi_remote: quinn::VarInt::from_u32(bidi_remote),
        uni: quinn::VarInt::from_u32(uni),
    }));
}

/// Order of the client's transport parameters (see `TransportConfig::transport_parameter_order`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TpOrder {
    Shuffled,
    Fixed(&'static [u64]),
    Rotated(&'static [u64]),
}

/// `version_information` shape; the chosen version is always QUIC v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VersionInfo {
    pub(crate) other_versions: &'static [VersionSlot],
    pub(crate) shuffle: bool,
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
    pub(crate) version_information: Option<VersionInfo>,
    pub(crate) extra_parameters: &'static [(u64, &'static [u8])],
    pub(crate) order: TpOrder,
    /// `active_connection_id_limit`; `None` keeps quinn's rule (5, or unsent with
    /// zero-length CIDs). At most 8 remote CIDs are held whatever is advertised.
    pub(crate) active_connection_id_limit: Option<u32>,
    /// Advertised `max_ack_delay` and the local delayed-ACK timer; 25 is the protocol
    /// default and is not written.
    pub(crate) max_ack_delay_ms: u32,
}

pub(crate) fn apply_browser_tp_options(
    transport: &mut quinn::TransportConfig,
    opts: &BrowserTpOptions,
) {
    let varints = |ids: &[u64]| -> Vec<quinn::VarInt> {
        ids.iter()
            .map(|id| quinn::VarInt::from_u64(*id).expect("TP id fits a varint"))
            .collect()
    };
    transport
        .advertise_min_ack_delay(opts.advertise_min_ack_delay)
        .send_grease_transport_parameter(opts.grease_parameter)
        .advertise_max_idle_timeout(opts.advertise_idle_timeout)
        .advertise_max_udp_payload_size(opts.advertise_max_udp_payload_size)
        .extra_transport_parameters(
            opts.extra_parameters
                .iter()
                .map(|(id, value)| {
                    (quinn::VarInt::from_u64(*id).expect("TP id fits a varint"), value.to_vec())
                })
                .collect(),
        )
        .transport_parameter_order(match opts.order {
            TpOrder::Shuffled => quinn_proto::TransportParameterOrder::Shuffled,
            TpOrder::Fixed(ids) => quinn_proto::TransportParameterOrder::Fixed(varints(ids)),
            TpOrder::Rotated(ids) => quinn_proto::TransportParameterOrder::Rotated(varints(ids)),
        })
        .version_information(opts.version_information.map(|vi| quinn_proto::VersionInformation {
            other_versions: vi.other_versions.to_vec(),
            shuffle: vi.shuffle,
        }))
        .advertised_active_connection_id_limit(
            opts.active_connection_id_limit.map(quinn::VarInt::from_u32),
        )
        .max_ack_delay_ms(opts.max_ack_delay_ms);
    match opts.datagram_frame_size {
        Some(size) => {
            transport
                .datagram_send_buffer_size(super::tls_config::H3_DATAGRAM_BUFFER_BYTES)
                .datagram_receive_buffer_size(Some(size as usize))
                .advertised_max_datagram_frame_size(Some(quinn::VarInt::from_u32(size)));
        },
        None => {
            transport.datagram_receive_buffer_size(None);
        },
    }
}
