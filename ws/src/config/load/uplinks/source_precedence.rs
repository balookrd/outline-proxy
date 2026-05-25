use url::Url;

use outline_transport::{FingerprintProfileStrategy, ServerAddr, TransportMode};
use outline_uplink::UplinkTransport;
use shadowsocks_crypto::CipherKind;

use crate::config::args::Args;
use crate::config::schema::{FallbackSection, OutlineSection, UplinkSection};

#[derive(Debug, Clone)]
pub(in crate::config::load) struct ResolvedUplinkInput {
    pub(super) name: String,
    pub(super) transport: Option<UplinkTransport>,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_mode: Option<TransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_mode: Option<TransportMode>,
    pub(super) vless_ws_url: Option<Url>,
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: Option<TransportMode>,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) cipher: Option<CipherKind>,
    pub(super) password: Option<String>,
    pub(super) weight: Option<f64>,
    pub(super) fwmark: Option<u32>,
    pub(super) ipv6_first: Option<bool>,
    pub(super) vless_id: Option<String>,
    /// Optional `vless://` share-link URI. When set, expands during
    /// `TryFrom<ResolvedUplinkInput>` into the matching VLESS fields and
    /// fails if any of them is already populated.
    pub(super) link: Option<String>,
    /// Per-uplink fingerprint-profile strategy override; `None` means
    /// inherit the top-level config knob. Threaded all the way to the
    /// `UplinkConfig.fingerprint_profile` field.
    pub(super) fingerprint_profile: Option<FingerprintProfileStrategy>,
    /// Optional list of fallback transports parsed from
    /// `[[outline.uplinks.fallbacks]]`. Validated at TryFrom time.
    pub(super) fallbacks: Vec<FallbackSection>,
    /// When `Some(true)`, the wire chain `[primary, fallbacks…]` is
    /// reshuffled once at config load and the runtime state machine
    /// surrenders to uplink-failover after one full round-trip without
    /// a single successful wire dial. See `UplinkSection::shuffle_wires`
    /// for the full semantics.
    pub(super) shuffle_wires: Option<bool>,
}

impl ResolvedUplinkInput {
    pub(super) fn from_cli(args: &Args, outline: Option<&OutlineSection>) -> Self {
        Self {
            name: "cli".to_string(),
            transport: args
                .transport
                .or_else(|| outline.and_then(|section| section.transport)),
            tcp_ws_url: args
                .tcp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.tcp_ws_url.clone())),
            tcp_mode: args.tcp_mode.or_else(|| outline.and_then(|section| section.tcp_mode)),
            udp_ws_url: args
                .udp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_ws_url.clone())),
            udp_mode: args.udp_mode.or_else(|| outline.and_then(|section| section.udp_mode)),
            vless_ws_url: args
                .vless_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.vless_ws_url.clone())),
            vless_xhttp_url: args
                .vless_xhttp_url
                .clone()
                .or_else(|| outline.and_then(|section| section.vless_xhttp_url.clone())),
            vless_mode: args
                .vless_mode
                .or_else(|| outline.and_then(|section| section.vless_mode)),
            tcp_addr: args
                .tcp_addr
                .clone()
                .or_else(|| outline.and_then(|section| section.tcp_addr.clone())),
            udp_addr: args
                .udp_addr
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_addr.clone())),
            cipher: args.method.or_else(|| outline.and_then(|section| section.method)),
            password: args
                .password
                .clone()
                .or_else(|| outline.and_then(|section| section.password.clone())),
            weight: Some(1.0),
            fwmark: args.fwmark.or_else(|| outline.and_then(|section| section.fwmark)),
            ipv6_first: args
                .ipv6_first
                .or_else(|| outline.and_then(|section| section.ipv6_first)),
            vless_id: None,
            link: args
                .vless_link
                .clone()
                .or_else(|| outline.and_then(|section| section.link.clone())),
            // CLI surface does not carry per-uplink fingerprint overrides
            // — operators reach for that knob via `[[outline.uplinks]]` in
            // the TOML, where multiple uplinks coexist. CLI builds a single
            // anonymous uplink, so inheriting the top-level value is fine.
            fingerprint_profile: None,
            // CLI does not yet expose fallback transports either — declare
            // them via `[[outline.uplinks.fallbacks]]` in the TOML.
            fallbacks: Vec::new(),
            // No CLI toggle for shuffle_wires; it is per-uplink and only
            // meaningful with multiple wires, both of which are TOML-only.
            shuffle_wires: None,
        }
    }

    pub(in crate::config::load) fn from_section(index: usize, uplink: &UplinkSection) -> Self {
        Self {
            name: uplink.name.clone().unwrap_or_else(|| format!("uplink-{}", index + 1)),
            transport: uplink.transport,
            tcp_ws_url: uplink.tcp_ws_url.clone(),
            tcp_mode: uplink.tcp_mode,
            udp_ws_url: uplink.udp_ws_url.clone(),
            udp_mode: uplink.udp_mode,
            vless_ws_url: uplink.vless_ws_url.clone(),
            vless_xhttp_url: uplink.vless_xhttp_url.clone(),
            vless_mode: uplink.vless_mode,
            tcp_addr: uplink.tcp_addr.clone(),
            udp_addr: uplink.udp_addr.clone(),
            cipher: uplink.method,
            password: uplink.password.clone(),
            weight: uplink.weight,
            fwmark: uplink.fwmark,
            ipv6_first: uplink.ipv6_first,
            vless_id: uplink.vless_id.clone(),
            link: uplink.link.clone(),
            fingerprint_profile: uplink.fingerprint_profile,
            fallbacks: uplink.fallbacks.clone().unwrap_or_default(),
            shuffle_wires: uplink.shuffle_wires,
        }
    }
}

pub(in crate::config::load) fn cli_uplink_override_requested(args: &Args) -> bool {
    args.tcp_ws_url.is_some()
        || args.transport.is_some()
        || args.tcp_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_mode.is_some()
        || args.vless_ws_url.is_some()
        || args.vless_xhttp_url.is_some()
        || args.vless_mode.is_some()
        || args.vless_link.is_some()
        || args.tcp_addr.is_some()
        || args.udp_addr.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some()
        || args.ipv6_first.is_some()
}
