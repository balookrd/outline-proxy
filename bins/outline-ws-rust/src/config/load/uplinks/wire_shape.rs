use anyhow::{Context, Result, anyhow, bail};
use url::Url;

use outline_transport::TransportMode;
use outline_uplink::{UplinkTransport, VlessShareLink};

pub(super) struct PrimaryWireInput<'a> {
    pub(super) name: &'a str,
    pub(super) transport: Option<UplinkTransport>,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_xhttp_url: Option<Url>,
    pub(super) tcp_mode: Option<TransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_xhttp_url: Option<Url>,
    pub(super) udp_mode: Option<TransportMode>,
    pub(super) vless_ws_url: Option<Url>,
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: Option<TransportMode>,
    pub(super) ss_ws_url: Option<Url>,
    pub(super) ss_xhttp_url: Option<Url>,
    pub(super) ss_mode: Option<TransportMode>,
    pub(super) vless_id: Option<String>,
    pub(super) link: Option<String>,
}

pub(super) struct PrimaryWireShape {
    pub(super) transport: UplinkTransport,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_xhttp_url: Option<Url>,
    pub(super) tcp_mode: TransportMode,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_xhttp_url: Option<Url>,
    pub(super) udp_mode: TransportMode,
    pub(super) vless_ws_url: Option<Url>,
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: TransportMode,
    pub(super) ss_ws_url: Option<Url>,
    pub(super) ss_xhttp_url: Option<Url>,
    pub(super) ss_mode: Option<TransportMode>,
    pub(super) vless_id: Option<String>,
}

pub(super) fn resolve_primary_wire_shape(input: PrimaryWireInput<'_>) -> Result<PrimaryWireShape> {
    let PrimaryWireInput {
        name,
        transport,
        tcp_ws_url,
        tcp_xhttp_url,
        tcp_mode,
        udp_ws_url,
        udp_xhttp_url,
        udp_mode,
        mut vless_ws_url,
        mut vless_xhttp_url,
        mut vless_mode,
        ss_ws_url,
        ss_xhttp_url,
        ss_mode,
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

    // Combined-path SS: `ss_xhttp_url` / `ss_ws_url` carry BOTH legs on one
    // URL, with `ss_mode` as the single carrier mode. Validate the shape here
    // (mutual exclusion + carrier consistency) before the per-transport gate;
    // a combined uplink then short-circuits the split SS branch below.
    let combined_ss =
        matches!(transport, UplinkTransport::Ss) && (ss_xhttp_url.is_some() || ss_ws_url.is_some());
    if combined_ss {
        if ss_xhttp_url.is_some() && ss_ws_url.is_some() {
            bail!(
                "uplink {name}: `ss_xhttp_url` and `ss_ws_url` are mutually exclusive — pick one combined carrier"
            );
        }
        if tcp_ws_url.is_some()
            || tcp_xhttp_url.is_some()
            || udp_ws_url.is_some()
            || udp_xhttp_url.is_some()
        {
            bail!(
                "uplink {name}: combined `ss_xhttp_url`/`ss_ws_url` is mutually exclusive with the split `tcp_*`/`udp_*` URL fields — remove the split URLs"
            );
        }
        let m = ss_mode.ok_or_else(|| {
            anyhow!("uplink {name}: combined `ss_xhttp_url`/`ss_ws_url` requires `ss_mode`")
        })?;
        if matches!(m, TransportMode::Quic) {
            bail!(
                "uplink {name}: combined mode does not support raw QUIC (it muxes tcp+udp on one connection natively)"
            );
        }
        #[cfg(not(feature = "h3"))]
        if matches!(m, TransportMode::XhttpH3 | TransportMode::WsH3) {
            bail!(
                "uplink {name}: ss_mode={m} requires the `h3` feature; \
                 rebuild with `--features h3` or pick a non-h3 mode"
            );
        }
        if ss_xhttp_url.is_some() && !m.is_xhttp() {
            bail!(
                "uplink {name}: `ss_xhttp_url` requires an XHTTP `ss_mode` (xhttp_h1/h2/h3), got {m}"
            );
        }
        if ss_ws_url.is_some() && m.is_xhttp() {
            bail!("uplink {name}: `ss_ws_url` requires a WS `ss_mode` (ws_h1/h2/h3), got {m}");
        }
    } else if ss_mode.is_some() || ss_xhttp_url.is_some() || ss_ws_url.is_some() {
        bail!(
            "uplink {name}: `ss_xhttp_url` / `ss_ws_url` / `ss_mode` are combined-path SS fields — valid only for transport=ss, and `ss_mode` requires one of the ss URLs"
        );
    }

    // Per-transport field gating: each transport owns a disjoint subset of
    // the WS/socket fields. Cross-population is rejected at parse time so
    // misconfiguration surfaces as a clear error rather than a confusing
    // dial failure later.
    let (
        tcp_ws_url,
        tcp_xhttp_url,
        tcp_mode,
        udp_ws_url,
        udp_xhttp_url,
        udp_mode,
        vless_ws_url,
        vless_xhttp_url,
        vless_mode,
    ) = match transport {
        UplinkTransport::Ss if combined_ss => {
            // Validated above: exactly one `ss_*_url`, `ss_mode` set + carrier
            // consistent, split fields empty. Both legs ride `ss_mode`; the
            // split URL fields stay None and the combined URLs pass through to
            // `PrimaryWireShape` (read back via `combined_ss_url`).
            let m = ss_mode.expect("combined_ss implies ss_mode (validated above)");
            (None, None, m, None, None, m, None, None, TransportMode::default())
        },
        UplinkTransport::Ss => {
            if vless_ws_url.is_some() || vless_xhttp_url.is_some() || vless_mode.is_some() {
                bail!(
                    "uplink {name}: `vless_ws_url`/`vless_xhttp_url`/`vless_mode` are only valid for transport=vless"
                );
            }
            let mode = tcp_mode.unwrap_or_default();
            let udp_mode = udp_mode.unwrap_or_default();
            // `xhttp_h3` / `ws_h3` need the QUIC + h3 stack behind the
            // optional `h3` feature on this binary (slim builds omit it).
            // Both the TCP and UDP carriers are checked.
            #[cfg(not(feature = "h3"))]
            for m in [mode, udp_mode] {
                if matches!(m, TransportMode::XhttpH3 | TransportMode::WsH3) {
                    bail!(
                        "uplink {name}: mode={m} requires the `h3` feature; \
                         rebuild with `--features h3` (the default profile already enables it) \
                         or pick a non-h3 mode"
                    );
                }
            }
            // Carrier ↔ URL cross-check: an XHTTP mode dials `*_xhttp_url`,
            // a WS mode dials `*_ws_url`. TCP requires the matching URL;
            // reject the other so a misconfig surfaces here, not at dial time.
            let (tcp_ws_url, tcp_xhttp_url) = if mode.is_xhttp() {
                if tcp_ws_url.is_some() {
                    bail!(
                        "uplink {name}: transport=ss with mode={mode} dials `tcp_xhttp_url`; remove `tcp_ws_url`"
                    );
                }
                let xhttp = tcp_xhttp_url.ok_or_else(|| {
                    anyhow!("uplink {name}: transport=ss with mode={mode} requires `tcp_xhttp_url`")
                })?;
                (None, Some(xhttp))
            } else {
                if tcp_xhttp_url.is_some() {
                    bail!(
                        "uplink {name}: transport=ss with mode={mode} dials `tcp_ws_url`; remove `tcp_xhttp_url`"
                    );
                }
                let ws = tcp_ws_url.ok_or_else(|| {
                    anyhow!("uplink {name}: transport=ss with mode={mode} requires `tcp_ws_url`")
                })?;
                (Some(ws), None)
            };
            // UDP is optional for SS (a TCP-only uplink leaves both unset),
            // so we only reject the wrong-URL-for-mode pairing — we do not
            // require a UDP URL.
            let (udp_ws_url, udp_xhttp_url) = if udp_mode.is_xhttp() {
                if udp_ws_url.is_some() {
                    bail!(
                        "uplink {name}: transport=ss with udp_mode={udp_mode} dials `udp_xhttp_url`; remove `udp_ws_url`"
                    );
                }
                (None, udp_xhttp_url)
            } else {
                if udp_xhttp_url.is_some() {
                    bail!(
                        "uplink {name}: transport=ss with udp_mode={udp_mode} dials `udp_ws_url`; remove `udp_xhttp_url`"
                    );
                }
                (udp_ws_url, None)
            };
            (
                tcp_ws_url,
                tcp_xhttp_url,
                mode,
                udp_ws_url,
                udp_xhttp_url,
                udp_mode,
                None,
                None,
                TransportMode::default(),
            )
        },
        UplinkTransport::Vless => {
            if tcp_ws_url.is_some()
                || tcp_xhttp_url.is_some()
                || tcp_mode.is_some()
                || udp_ws_url.is_some()
                || udp_xhttp_url.is_some()
                || udp_mode.is_some()
            {
                bail!(
                    "uplink {name}: `tcp_ws_url`/`tcp_xhttp_url`/`tcp_mode`/`udp_ws_url`/`udp_xhttp_url`/`udp_mode` are not valid for transport=vless; use `vless_ws_url`/`vless_xhttp_url`/`vless_mode` instead (the VLESS server exposes a single path for both TCP and UDP)"
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
                None,
                TransportMode::default(),
                None,
                None,
                TransportMode::default(),
                vless_ws_url,
                vless_xhttp_url,
                mode,
            )
        },
    };

    Ok(PrimaryWireShape {
        transport,
        tcp_ws_url,
        tcp_xhttp_url,
        tcp_mode,
        udp_ws_url,
        udp_xhttp_url,
        udp_mode,
        vless_ws_url,
        vless_xhttp_url,
        vless_mode,
        ss_ws_url,
        ss_xhttp_url,
        ss_mode,
        vless_id,
    })
}
