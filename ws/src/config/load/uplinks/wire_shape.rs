use anyhow::{anyhow, bail, Context, Result};
use url::Url;

use outline_transport::{ServerAddr, TransportMode};
use outline_uplink::{UplinkTransport, VlessShareLink};

pub(super) struct PrimaryWireInput<'a> {
    pub(super) name: &'a str,
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
    pub(super) vless_id: Option<String>,
    pub(super) link: Option<String>,
}

pub(super) struct PrimaryWireShape {
    pub(super) transport: UplinkTransport,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_mode: TransportMode,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_mode: TransportMode,
    pub(super) vless_ws_url: Option<Url>,
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: TransportMode,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) vless_id: Option<String>,
}

pub(super) fn resolve_primary_wire_shape(input: PrimaryWireInput<'_>) -> Result<PrimaryWireShape> {
    let PrimaryWireInput {
        name,
        transport,
        tcp_ws_url,
        tcp_mode,
        udp_ws_url,
        udp_mode,
        mut vless_ws_url,
        mut vless_xhttp_url,
        mut vless_mode,
        tcp_addr,
        udp_addr,
        mut vless_id,
        link,
    } = input;

    // `link = "vless://..."` populates the VLESS fields from a single
    // share-link URI. We do this before the transport-default fold so
    // a bare `link` entry implies `transport = "vless"` without the
    // user having to say so twice.
    let transport = if let Some(raw_link) = link.as_deref() {
        let parsed = VlessShareLink::parse(raw_link)
            .with_context(|| format!("uplink {name}: invalid vless share link"))?;
        if vless_id.is_some() {
            bail!("uplink {name}: `vless_id` is mutually exclusive with `link`; remove one");
        }
        if vless_ws_url.is_some() {
            bail!("uplink {name}: `vless_ws_url` is mutually exclusive with `link`; remove one");
        }
        if vless_xhttp_url.is_some() {
            bail!("uplink {name}: `vless_xhttp_url` is mutually exclusive with `link`; remove one");
        }
        if vless_mode.is_some() {
            bail!("uplink {name}: `vless_mode` is mutually exclusive with `link`; remove one");
        }
        match transport {
            None | Some(UplinkTransport::Vless) => {},
            Some(other) => bail!(
                "uplink {name}: `link` only applies to transport=vless, but transport={other} was set"
            ),
        }
        vless_id = Some(parsed.uuid);
        vless_ws_url = parsed.vless_ws_url;
        vless_xhttp_url = parsed.vless_xhttp_url;
        vless_mode = Some(parsed.mode);
        UplinkTransport::Vless
    } else {
        transport.unwrap_or_default()
    };

    // Per-transport field gating: each transport owns a disjoint subset of
    // the WS/socket fields. Cross-population is rejected at parse time so
    // misconfiguration surfaces as a clear error rather than a confusing
    // dial failure later.
    let (
        tcp_ws_url,
        tcp_mode,
        udp_ws_url,
        udp_mode,
        vless_ws_url,
        vless_xhttp_url,
        vless_mode,
        tcp_addr,
        udp_addr,
    ) = match transport {
        UplinkTransport::Ws => {
            if vless_ws_url.is_some() || vless_xhttp_url.is_some() || vless_mode.is_some() {
                bail!(
                    "uplink {name}: `vless_ws_url`/`vless_xhttp_url`/`vless_mode` are only valid for transport=vless"
                );
            }
            if tcp_addr.is_some() || udp_addr.is_some() {
                bail!(
                    "uplink {name}: `tcp_addr`/`udp_addr` are only valid for transport=shadowsocks"
                );
            }
            let tcp_ws_url = Some(
                tcp_ws_url
                    .ok_or_else(|| anyhow!("uplink {name}: transport=ws requires `tcp_ws_url`"))?,
            );
            (
                tcp_ws_url,
                tcp_mode.unwrap_or_default(),
                udp_ws_url,
                udp_mode.unwrap_or_default(),
                None,
                None,
                TransportMode::default(),
                None,
                None,
            )
        },
        UplinkTransport::Vless => {
            if tcp_ws_url.is_some()
                || tcp_mode.is_some()
                || udp_ws_url.is_some()
                || udp_mode.is_some()
            {
                bail!(
                    "uplink {name}: `tcp_ws_url`/`tcp_mode`/`udp_ws_url`/`udp_mode` are not valid for transport=vless; use `vless_ws_url`/`vless_xhttp_url`/`vless_mode` instead (the VLESS server exposes a single path for both TCP and UDP)"
                );
            }
            if tcp_addr.is_some() || udp_addr.is_some() {
                bail!(
                    "uplink {name}: `tcp_addr`/`udp_addr` are only valid for transport=shadowsocks"
                );
            }
            let mode = vless_mode.unwrap_or_default();
            // `xhttp_h3`, `ws_h3` and `quic` all need the QUIC + h3 stack
            // that lives behind the optional `h3` feature on this binary.
            #[cfg(not(feature = "h3"))]
            if matches!(mode, TransportMode::XhttpH3 | TransportMode::WsH3 | TransportMode::Quic) {
                bail!(
                    "uplink {name}: mode={mode} requires the `h3` feature; \
                     rebuild with `--features h3` (the default profile already enables it) \
                     or pick a non-h3 mode"
                );
            }
            // Cross-check: the URL field carrying the dial target must match
            // the chosen mode. Forgetting either is a common mistake; surface
            // it as a clear error rather than a confusing dial-time failure.
            let needs_xhttp_url = matches!(
                mode,
                TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3
            );
            let needs_ws_url = !needs_xhttp_url;
            if needs_ws_url && vless_ws_url.is_none() {
                bail!("uplink {name}: transport=vless with mode={mode} requires `vless_ws_url`");
            }
            if needs_xhttp_url && vless_xhttp_url.is_none() {
                bail!("uplink {name}: transport=vless with mode={mode} requires `vless_xhttp_url`");
            }
            (
                None,
                TransportMode::default(),
                None,
                TransportMode::default(),
                vless_ws_url,
                vless_xhttp_url,
                mode,
                None,
                None,
            )
        },
        UplinkTransport::Shadowsocks => {
            if tcp_ws_url.is_some()
                || tcp_mode.is_some()
                || udp_ws_url.is_some()
                || udp_mode.is_some()
                || vless_ws_url.is_some()
                || vless_xhttp_url.is_some()
                || vless_mode.is_some()
            {
                bail!(
                    "uplink {name}: websocket uplink fields are not valid for transport=shadowsocks; use `tcp_addr`/`udp_addr`"
                );
            }
            let tcp_addr = Some(tcp_addr.ok_or_else(|| {
                anyhow!("uplink {name}: transport=shadowsocks requires `tcp_addr`")
            })?);
            (
                None,
                TransportMode::default(),
                None,
                TransportMode::default(),
                None,
                None,
                TransportMode::default(),
                tcp_addr,
                udp_addr,
            )
        },
    };

    Ok(PrimaryWireShape {
        transport,
        tcp_ws_url,
        tcp_mode,
        udp_ws_url,
        udp_mode,
        vless_ws_url,
        vless_xhttp_url,
        vless_mode,
        tcp_addr,
        udp_addr,
        vless_id,
    })
}
