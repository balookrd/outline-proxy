use anyhow::{Context, Result, anyhow, bail};
use url::Url;

use outline_transport::TransportMode;
use outline_uplink::{SsShareLink, UplinkTransport, VlessShareLink};
use shadowsocks_crypto::CipherKind;

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
    /// SS cipher / password as configured explicitly (CLI / TOML). An
    /// `ss://` share link populates these from its userinfo instead — the
    /// two are mutually exclusive. Threaded through here (like `vless_id`)
    /// so `resolve_primary_credentials` sees the link-derived values.
    pub(super) cipher: Option<CipherKind>,
    pub(super) password: Option<String>,
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
    /// SS credentials, resolved from either the explicit fields or an
    /// `ss://` share link. Consumed by `resolve_primary_credentials`.
    pub(super) cipher: Option<CipherKind>,
    pub(super) password: Option<String>,
}

/// Which explicit fields the caller carries. A share link makes them
/// redundant, so a set flag aborts the load with a uniform message instead of
/// silently letting one source win over the other.
///
/// `method` / `password` are deliberately checked only against an `ss://`
/// link: an `ss://` URI carries the credentials itself, while a `vless://`
/// uplink may legitimately keep them for its SS fallbacks to inherit.
pub(super) struct LinkConflictFields {
    pub(super) tcp_ws_url: bool,
    pub(super) tcp_xhttp_url: bool,
    pub(super) tcp_mode: bool,
    pub(super) udp_ws_url: bool,
    pub(super) udp_xhttp_url: bool,
    pub(super) udp_mode: bool,
    pub(super) vless_ws_url: bool,
    pub(super) vless_xhttp_url: bool,
    pub(super) vless_mode: bool,
    pub(super) ss_ws_url: bool,
    pub(super) ss_xhttp_url: bool,
    pub(super) ss_mode: bool,
    pub(super) vless_id: bool,
    pub(super) method: bool,
    pub(super) password: bool,
}

/// Wire fields a share-link URI expands into.
pub(super) struct LinkExpansion {
    pub(super) transport: UplinkTransport,
    pub(super) vless_ws_url: Option<Url>,
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: Option<TransportMode>,
    pub(super) ss_ws_url: Option<Url>,
    pub(super) ss_xhttp_url: Option<Url>,
    pub(super) ss_mode: Option<TransportMode>,
    pub(super) vless_id: Option<String>,
    pub(super) cipher: Option<CipherKind>,
    pub(super) password: Option<String>,
}

/// Expand a `vless://` / `ss://` share link into wire fields.
///
/// Shared by the primary wire (`[[outline.uplinks]] link`) and the fallback
/// pre-pass (`[[outline.uplinks.fallbacks]] link`) so both surfaces agree on
/// which transport a link implies, which explicit fields it conflicts with and
/// how that conflict reads. `context` prefixes every error — `uplink edge-1`
/// or `uplink edge-1: fallbacks[2]`.
pub(super) fn expand_share_link(
    context: &str,
    link: &str,
    declared: Option<UplinkTransport>,
    conflicts: LinkConflictFields,
) -> Result<LinkExpansion> {
    let trimmed = link.trim();
    if trimmed.starts_with("ss://") {
        let parsed = SsShareLink::parse(trimmed)
            .with_context(|| format!("{context}: invalid ss share link"))?;
        // An `ss://` link carries a combined-path carrier *and* the
        // credentials, so it conflicts with every explicit wire field.
        for (set, field) in [
            (conflicts.vless_id, "vless_id"),
            (conflicts.vless_ws_url, "vless_ws_url"),
            (conflicts.vless_xhttp_url, "vless_xhttp_url"),
            (conflicts.vless_mode, "vless_mode"),
            (conflicts.ss_ws_url, "ss_ws_url"),
            (conflicts.ss_xhttp_url, "ss_xhttp_url"),
            (conflicts.ss_mode, "ss_mode"),
            (conflicts.method, "method"),
            (conflicts.password, "password"),
            (conflicts.tcp_ws_url, "tcp_ws_url"),
            (conflicts.tcp_xhttp_url, "tcp_xhttp_url"),
            (conflicts.tcp_mode, "tcp_mode"),
            (conflicts.udp_ws_url, "udp_ws_url"),
            (conflicts.udp_xhttp_url, "udp_xhttp_url"),
            (conflicts.udp_mode, "udp_mode"),
        ] {
            if set {
                bail!(
                    "{context}: `{field}` is mutually exclusive with an `ss://` `link`; remove one"
                );
            }
        }
        match declared {
            None | Some(UplinkTransport::Ss) => {},
            Some(other) => bail!(
                "{context}: an `ss://` `link` only applies to transport=ss, but transport={other} was set"
            ),
        }
        Ok(LinkExpansion {
            transport: UplinkTransport::Ss,
            vless_ws_url: None,
            vless_xhttp_url: None,
            vless_mode: None,
            ss_ws_url: parsed.ss_ws_url,
            ss_xhttp_url: parsed.ss_xhttp_url,
            ss_mode: Some(parsed.mode),
            vless_id: None,
            cipher: Some(parsed.cipher),
            password: Some(parsed.password),
        })
    } else {
        let parsed = VlessShareLink::parse(trimmed)
            .with_context(|| format!("{context}: invalid vless share link"))?;
        for (set, field) in [
            (conflicts.vless_id, "vless_id"),
            (conflicts.vless_ws_url, "vless_ws_url"),
            (conflicts.vless_xhttp_url, "vless_xhttp_url"),
            (conflicts.vless_mode, "vless_mode"),
            (conflicts.ss_ws_url, "ss_ws_url"),
            (conflicts.ss_xhttp_url, "ss_xhttp_url"),
            (conflicts.ss_mode, "ss_mode"),
            (conflicts.tcp_ws_url, "tcp_ws_url"),
            (conflicts.tcp_xhttp_url, "tcp_xhttp_url"),
            (conflicts.tcp_mode, "tcp_mode"),
            (conflicts.udp_ws_url, "udp_ws_url"),
            (conflicts.udp_xhttp_url, "udp_xhttp_url"),
            (conflicts.udp_mode, "udp_mode"),
        ] {
            if set {
                bail!("{context}: `{field}` is mutually exclusive with `link`; remove one");
            }
        }
        match declared {
            None | Some(UplinkTransport::Vless) => {},
            Some(other) => bail!(
                "{context}: a `vless://` `link` only applies to transport=vless, but transport={other} was set"
            ),
        }
        Ok(LinkExpansion {
            transport: UplinkTransport::Vless,
            vless_ws_url: parsed.vless_ws_url,
            vless_xhttp_url: parsed.vless_xhttp_url,
            vless_mode: Some(parsed.mode),
            ss_ws_url: None,
            ss_xhttp_url: None,
            ss_mode: None,
            vless_id: Some(parsed.uuid),
            cipher: None,
            password: None,
        })
    }
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
        mut ss_ws_url,
        mut ss_xhttp_url,
        mut ss_mode,
        mut vless_id,
        mut cipher,
        mut password,
        link,
    } = input;

    // `link = "vless://..."` / `"ss://..."` populates the matching transport
    // fields from a single share-link URI. We do this before the
    // transport-default fold so a bare `link` entry implies its transport
    // (`vless` for `vless://`, `ss` for `ss://`) without the user saying so
    // twice. The scheme picks the parser.
    let transport = if let Some(raw_link) = link.as_deref() {
        let expansion = expand_share_link(
            &format!("uplink {name}"),
            raw_link,
            transport,
            LinkConflictFields {
                tcp_ws_url: tcp_ws_url.is_some(),
                tcp_xhttp_url: tcp_xhttp_url.is_some(),
                tcp_mode: tcp_mode.is_some(),
                udp_ws_url: udp_ws_url.is_some(),
                udp_xhttp_url: udp_xhttp_url.is_some(),
                udp_mode: udp_mode.is_some(),
                vless_ws_url: vless_ws_url.is_some(),
                vless_xhttp_url: vless_xhttp_url.is_some(),
                vless_mode: vless_mode.is_some(),
                ss_ws_url: ss_ws_url.is_some(),
                ss_xhttp_url: ss_xhttp_url.is_some(),
                ss_mode: ss_mode.is_some(),
                vless_id: vless_id.is_some(),
                method: cipher.is_some(),
                password: password.is_some(),
            },
        )?;
        vless_ws_url = expansion.vless_ws_url;
        vless_xhttp_url = expansion.vless_xhttp_url;
        vless_mode = expansion.vless_mode;
        ss_ws_url = expansion.ss_ws_url;
        ss_xhttp_url = expansion.ss_xhttp_url;
        ss_mode = expansion.ss_mode;
        vless_id = expansion.vless_id;
        if expansion.cipher.is_some() {
            cipher = expansion.cipher;
        }
        if expansion.password.is_some() {
            password = expansion.password;
        }
        expansion.transport
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
            // `xhttp_h3` and `ws_h3` both need the QUIC + h3 stack that lives
            // behind the optional `h3` feature on this binary.
            #[cfg(not(feature = "h3"))]
            if matches!(mode, TransportMode::XhttpH3 | TransportMode::WsH3) {
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
        cipher,
        password,
    })
}
