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

/// How the ClientHello is laid out in CRYPTO frames across the Initials (see
/// `TransportConfig::initial_crypto_layout`). Initials stay at 1200 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelloLayout {
    /// One CRYPTO frame per Initial, filled in order (upstream quinn).
    Contiguous,
    /// Chrome's chaos protection: an even split with head and tail first, extra CRYPTO
    /// frames, PINGs and PADDING scattered in a shuffled order.
    Chaos,
    /// Firefox's SNI slicing: an even split cut in the middle of the SNI, tail first.
    SniSlice,
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
    pub(crate) hello_layout: HelloLayout,
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
        .max_ack_delay_ms(opts.max_ack_delay_ms)
        .initial_crypto_layout(match opts.hello_layout {
            HelloLayout::Contiguous => quinn_proto::InitialCryptoLayout::Contiguous,
            HelloLayout::Chaos => quinn_proto::InitialCryptoLayout::Chaos,
            HelloLayout::SniSlice => quinn_proto::InitialCryptoLayout::SniSlice,
        });
    match opts.datagram_frame_size {
        Some(size) => {
            transport
                .datagram_send_buffer_size(super::tls_config::H3_DATAGRAM_BUFFER_BYTES)
                // Local only: room for datagrams the demultiplexer has not read
                // yet, so a short stall of its task does not silently drop
                // them. The peer sees `advertised_max_datagram_frame_size`.
                .datagram_receive_buffer_size(Some(super::tls_config::H3_DATAGRAM_BUFFER_BYTES))
                .advertised_max_datagram_frame_size(Some(quinn::VarInt::from_u32(size)));
        },
        None => {
            transport.datagram_receive_buffer_size(None);
        },
    }
}

/// First DPLPMTUD probe of a dial (`MtuDiscoveryConfig::first_probe`). `caps` keeps the
/// probe's outcome as the connection's ceiling (`first_probe_caps`); a seed only replaces
/// the ladder and leaves the search free to go above it, and the connection is capped
/// below the smallest size that search rejects, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FirstProbe {
    pub(crate) size: u16,
    pub(crate) caps: bool,
}

impl FirstProbe {
    pub(crate) const fn capped(size: u16) -> Self {
        Self { size, caps: true }
    }

    pub(crate) const fn seed(size: u16) -> Self {
        Self { size, caps: false }
    }
}

/// `None` keeps upstream's binary search from the start.
pub(crate) fn set_mtu_first_probe(
    mtu: &mut quinn::MtuDiscoveryConfig,
    first_probe: Option<FirstProbe>,
) {
    mtu.first_probe(first_probe.map(|p| p.size))
        .first_probe_caps(first_probe.is_none_or(|p| p.caps));
}

/// Whether the path MTU search has finished (`PathStats::plpmtud_settled`): a
/// `current_mtu` read before that is a mid-search value.
#[cfg(feature = "h3")]
pub(crate) fn path_mtu_settled(path: &quinn::PathStats) -> bool {
    path.plpmtud_settled
}
