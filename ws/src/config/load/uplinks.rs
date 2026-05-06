use anyhow::{Context, Result, anyhow, bail};
use url::Url;

use outline_transport::{ServerAddr, TransportMode};
use outline_uplink::{FallbackTransport, UplinkConfig, UplinkTransport, VlessShareLink};
use shadowsocks_crypto::CipherKind;

use super::super::args::Args;
use super::super::schema::{FallbackSection, OutlineSection, UplinkSection};

#[derive(Debug, Clone)]
pub(super) struct ResolvedUplinkInput {
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
    pub(super) fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
    /// Optional list of fallback transports parsed from
    /// `[[outline.uplinks.fallbacks]]`. Validated at TryFrom time.
    pub(super) fallbacks: Vec<FallbackSection>,
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
            tcp_mode: args
                .tcp_mode
                .or_else(|| outline.and_then(|section| section.tcp_mode)),
            udp_ws_url: args
                .udp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_ws_url.clone())),
            udp_mode: args
                .udp_mode
                .or_else(|| outline.and_then(|section| section.udp_mode)),
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
        }
    }

    pub(super) fn from_section(index: usize, uplink: &UplinkSection) -> Self {
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
        }
    }

}

impl TryFrom<ResolvedUplinkInput> for UplinkConfig {
    type Error = anyhow::Error;

    fn try_from(input: ResolvedUplinkInput) -> Result<Self> {
        // The `fallbacks` field is consumed by name later (after `parent` is
        // built); destructure everything else here so the rest of the body
        // can stay shape-compatible with the pre-fallback form.
        let input_fallbacks = input.fallbacks.clone();
        let ResolvedUplinkInput {
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
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first,
            mut vless_id,
            link,
            fingerprint_profile,
            fallbacks: _,
        } = input;

        // `link = "vless://..."` populates the VLESS fields from a single
        // share-link URI. We do this before the transport-default fold so
        // a bare `link` entry implies `transport = "vless"` without the
        // user having to say so twice.
        let transport = if let Some(raw_link) = link.as_deref() {
            let parsed = VlessShareLink::parse(raw_link)
                .with_context(|| format!("uplink {name}: invalid vless share link"))?;
            if vless_id.is_some() {
                bail!(
                    "uplink {name}: `vless_id` is mutually exclusive with `link`; remove one"
                );
            }
            if vless_ws_url.is_some() {
                bail!(
                    "uplink {name}: `vless_ws_url` is mutually exclusive with `link`; remove one"
                );
            }
            if vless_xhttp_url.is_some() {
                bail!(
                    "uplink {name}: `vless_xhttp_url` is mutually exclusive with `link`; remove one"
                );
            }
            if vless_mode.is_some() {
                bail!(
                    "uplink {name}: `vless_mode` is mutually exclusive with `link`; remove one"
                );
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

        let weight = weight.unwrap_or(1.0);
        if !weight.is_finite() || weight <= 0.0 {
            bail!("uplink weight must be a finite positive number");
        }
        let is_vless = transport == UplinkTransport::Vless;
        let cipher = cipher.unwrap_or(CipherKind::Chacha20IetfPoly1305);
        let password = if is_vless {
            // VLESS has no shared secret; keep an empty placeholder so the
            // shared `UplinkConfig` struct stays uniform.
            password.unwrap_or_default()
        } else {
            let pw = password.ok_or_else(|| {
                anyhow!("missing password: set it in config.toml or pass --password")
            })?;
            cipher
                .derive_master_key(&pw)
                .with_context(|| format!("invalid password/PSK for cipher {cipher}"))?;
            pw
        };

        let vless_id = if is_vless {
            let raw = vless_id.ok_or_else(|| {
                anyhow!("uplink {name}: transport=vless requires `vless_id = \"…\"`")
            })?;
            Some(outline_transport::vless::parse_uuid(&raw).with_context(|| {
                format!("uplink {name}: invalid vless_id")
            })?)
        } else {
            if vless_id.is_some() {
                bail!("uplink {name}: `vless_id` is only valid for transport=vless");
            }
            None
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
                    if vless_ws_url.is_some()
                        || vless_xhttp_url.is_some()
                        || vless_mode.is_some()
                    {
                        bail!(
                            "uplink {name}: `vless_ws_url`/`vless_xhttp_url`/`vless_mode` are only valid for transport=vless"
                        );
                    }
                    if tcp_addr.is_some() || udp_addr.is_some() {
                        bail!(
                            "uplink {name}: `tcp_addr`/`udp_addr` are only valid for transport=shadowsocks"
                        );
                    }
                    let tcp_ws_url = Some(tcp_ws_url.ok_or_else(|| {
                        anyhow!("uplink {name}: transport=ws requires `tcp_ws_url`")
                    })?);
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
                    // `xhttp_h3`, `ws_h3` and `quic` all need the
                    // QUIC + h3 stack that lives behind the optional
                    // `h3` feature on this binary (it pulls
                    // `outline-transport/h3` and `outline-uplink/quic`
                    // transitively). Catch the build-time mismatch at
                    // config load instead of as a confusing dial-time
                    // failure deep in the dispatcher.
                    #[cfg(not(feature = "h3"))]
                    if matches!(
                        mode,
                        TransportMode::XhttpH3 | TransportMode::WsH3 | TransportMode::Quic
                    ) {
                        bail!(
                            "uplink {name}: mode={mode} requires the `h3` feature; \
                             rebuild with `--features h3` (the default profile already enables it) \
                             or pick a non-h3 mode"
                        );
                    }
                    // Cross-check: the URL field carrying the dial target
                    // must match the chosen mode. Forgetting either is a
                    // common mistake; surface it as a clear error rather
                    // than a confusing dial-time failure.
                    let needs_xhttp_url = matches!(
                        mode,
                        TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3
                    );
                    let needs_ws_url = !needs_xhttp_url;
                    if needs_ws_url && vless_ws_url.is_none() {
                        bail!(
                            "uplink {name}: transport=vless with mode={mode} requires `vless_ws_url`"
                        );
                    }
                    if needs_xhttp_url && vless_xhttp_url.is_none() {
                        bail!(
                            "uplink {name}: transport=vless with mode={mode} requires `vless_xhttp_url`"
                        );
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

        let parent = UplinkConfig {
            name,
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
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first: ipv6_first.unwrap_or(false),
            vless_id,
            fingerprint_profile,
            fallbacks: Vec::new(),
        };

        // ── Fallback transports ─────────────────────────────────────────────
        // Validated against the now-resolved primary so error messages can
        // refer to the parent's `name` and reject same-transport entries
        // before we reach the dial loop.
        let mut fallbacks: Vec<FallbackTransport> = Vec::with_capacity(input_fallbacks.len());
        for (idx, section) in input_fallbacks.iter().enumerate() {
            let fb = resolve_fallback(&parent, section, idx)?;
            // Disallow duplicates per `transport`; one fallback per kind is
            // already enough for the only sane chain shape (vless → ws → ss).
            if fallbacks.iter().any(|existing| existing.transport == fb.transport) {
                bail!(
                    "uplink {}: fallbacks[{}] declares transport={} a second time; \
                     each fallback transport must be unique",
                    parent.name,
                    idx,
                    fb.transport,
                );
            }
            fallbacks.push(fb);
        }
        Ok(UplinkConfig { fallbacks, ..parent })
    }
}

/// Validate a single `[[outline.uplinks.fallbacks]]` entry against the parent's
/// resolved shape. Inheritance: `cipher` / `password` / `fwmark` / `ipv6_first`
/// / `fingerprint_profile` default to the parent's value when omitted; URLs /
/// addrs / `vless_id` are not inherited (they are inherently per-wire).
fn resolve_fallback(
    parent: &UplinkConfig,
    section: &FallbackSection,
    idx: usize,
) -> Result<FallbackTransport> {
    let parent_name = &parent.name;
    let transport = section.transport;

    if transport == parent.transport {
        bail!(
            "uplink {parent_name}: fallbacks[{idx}] declares transport={transport} which \
             matches the parent uplink's primary transport — a fallback must use a \
             different wire family"
        );
    }

    // Inherited fields (parent → fallback default).
    let cipher = section.method.unwrap_or(parent.cipher);
    let fwmark = section.fwmark.or(parent.fwmark);
    let ipv6_first = section.ipv6_first.unwrap_or(parent.ipv6_first);
    let fingerprint_profile = section.fingerprint_profile.or(parent.fingerprint_profile);
    let password_inherited = section.password.clone().unwrap_or_else(|| parent.password.clone());

    let mut tcp_ws_url = section.tcp_ws_url.clone();
    let mut tcp_mode = section.tcp_mode;
    let mut udp_ws_url = section.udp_ws_url.clone();
    let mut udp_mode = section.udp_mode;
    let mut vless_ws_url = section.vless_ws_url.clone();
    let mut vless_xhttp_url = section.vless_xhttp_url.clone();
    let mut vless_mode = section.vless_mode;
    let mut tcp_addr = section.tcp_addr.clone();
    let mut udp_addr = section.udp_addr.clone();

    // Per-transport gating: each wire family owns a disjoint subset of the
    // fields. Cross-population is rejected at parse time so misconfiguration
    // surfaces as a clear error rather than a confusing dial-time failure.
    let (final_password, final_vless_id) = match transport {
        UplinkTransport::Ws => {
            if vless_ws_url.is_some() || vless_xhttp_url.is_some() || vless_mode.is_some() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=ws) must not set \
                     `vless_ws_url`/`vless_xhttp_url`/`vless_mode`"
                );
            }
            if tcp_addr.is_some() || udp_addr.is_some() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=ws) must not set \
                     `tcp_addr`/`udp_addr`"
                );
            }
            if section.vless_id.is_some() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=ws) must not set \
                     `vless_id`"
                );
            }
            if tcp_ws_url.is_none() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=ws) requires \
                     `tcp_ws_url`"
                );
            }
            tcp_mode = Some(tcp_mode.unwrap_or_default());
            udp_mode = Some(udp_mode.unwrap_or_default());
            vless_mode = Some(TransportMode::default());
            // Validate password against cipher (skipped on inherit-only path
            // when parent already validated).
            cipher
                .derive_master_key(&password_inherited)
                .with_context(|| {
                    format!(
                        "uplink {parent_name}: fallbacks[{idx}] invalid password/PSK \
                         for cipher {cipher}"
                    )
                })?;
            (password_inherited, None)
        },
        UplinkTransport::Vless => {
            if tcp_ws_url.is_some()
                || tcp_mode.is_some()
                || udp_ws_url.is_some()
                || udp_mode.is_some()
            {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=vless) must not set \
                     `tcp_ws_url`/`tcp_mode`/`udp_ws_url`/`udp_mode`; use \
                     `vless_ws_url`/`vless_xhttp_url`/`vless_mode`"
                );
            }
            if tcp_addr.is_some() || udp_addr.is_some() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=vless) must not set \
                     `tcp_addr`/`udp_addr`"
                );
            }
            let mode = vless_mode.unwrap_or_default();
            #[cfg(not(feature = "h3"))]
            if matches!(
                mode,
                TransportMode::XhttpH3 | TransportMode::WsH3 | TransportMode::Quic
            ) {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] mode={mode} requires the \
                     `h3` feature"
                );
            }
            let needs_xhttp_url = matches!(
                mode,
                TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3
            );
            if needs_xhttp_url && vless_xhttp_url.is_none() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=vless mode={mode}) \
                     requires `vless_xhttp_url`"
                );
            }
            if !needs_xhttp_url && vless_ws_url.is_none() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=vless mode={mode}) \
                     requires `vless_ws_url`"
                );
            }
            // VLESS uuid is per-wire-credential and *not* inherited from
            // the parent (different VLESS endpoints use different uuids).
            let raw = section.vless_id.as_deref().ok_or_else(|| {
                anyhow!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=vless) requires \
                     `vless_id` (it is not inherited from the parent uplink)"
                )
            })?;
            let parsed_id = outline_transport::vless::parse_uuid(raw).with_context(|| {
                format!("uplink {parent_name}: fallbacks[{idx}] invalid vless_id")
            })?;
            vless_mode = Some(mode);
            tcp_mode = Some(TransportMode::default());
            udp_mode = Some(TransportMode::default());
            // VLESS has no shared secret; password is irrelevant on this wire.
            (String::new(), Some(parsed_id))
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
                    "uplink {parent_name}: fallbacks[{idx}] (transport=shadowsocks) must not \
                     set websocket fields; use `tcp_addr`/`udp_addr`"
                );
            }
            if section.vless_id.is_some() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=shadowsocks) must not \
                     set `vless_id`"
                );
            }
            if tcp_addr.is_none() {
                bail!(
                    "uplink {parent_name}: fallbacks[{idx}] (transport=shadowsocks) requires \
                     `tcp_addr`"
                );
            }
            tcp_mode = Some(TransportMode::default());
            udp_mode = Some(TransportMode::default());
            vless_mode = Some(TransportMode::default());
            // Shadowsocks needs the shared key validated against the cipher
            // (mirrors the primary-path check).
            cipher
                .derive_master_key(&password_inherited)
                .with_context(|| {
                    format!(
                        "uplink {parent_name}: fallbacks[{idx}] invalid password/PSK \
                         for cipher {cipher}"
                    )
                })?;
            (password_inherited, None)
        },
    };

    // Field nulling for fields that don't apply to the chosen transport,
    // mirroring the post-validation shape `UplinkConfig` carries.
    match transport {
        UplinkTransport::Ws => {
            vless_ws_url = None;
            vless_xhttp_url = None;
            tcp_addr = None;
            udp_addr = None;
        },
        UplinkTransport::Vless => {
            tcp_ws_url = None;
            udp_ws_url = None;
            tcp_addr = None;
            udp_addr = None;
        },
        UplinkTransport::Shadowsocks => {
            tcp_ws_url = None;
            udp_ws_url = None;
            vless_ws_url = None;
            vless_xhttp_url = None;
        },
    }

    Ok(FallbackTransport {
        transport,
        tcp_ws_url,
        tcp_mode: tcp_mode.unwrap_or_default(),
        udp_ws_url,
        udp_mode: udp_mode.unwrap_or_default(),
        vless_ws_url,
        vless_xhttp_url,
        vless_mode: vless_mode.unwrap_or_default(),
        vless_id: final_vless_id,
        tcp_addr,
        udp_addr,
        cipher,
        password: final_password,
        fwmark,
        ipv6_first,
        fingerprint_profile,
    })
}

pub(super) fn load_uplinks(
    outline: Option<&OutlineSection>,
    args: &Args,
) -> Result<Vec<UplinkConfig>> {
    if cli_uplink_override_requested(args) {
        return Ok(vec![ResolvedUplinkInput::from_cli(args, outline).try_into()?]);
    }

    // After compat normalisation, `outline.uplinks` is guaranteed populated
    // whenever any uplink-definition field is set — either explicitly via
    // `[[uplinks]]` or synthesised from inline fields. The only way to land
    // here with `None` is a config that truly declares no uplink.
    let uplinks = outline.and_then(|o| o.uplinks.as_ref()).ok_or_else(|| {
        anyhow!(
            "no uplink configured: add an [outline] section (or at least `password` + \
             `tcp_ws_url`/`tcp_addr`), use `[[uplink_group]]`, or pass CLI overrides"
        )
    })?;
    if uplinks.is_empty() {
        bail!("uplinks is present but empty");
    }

    uplinks
        .iter()
        .enumerate()
        .map(|(index, uplink)| ResolvedUplinkInput::from_section(index, uplink).try_into())
        .collect()
}

/// Validate a single `[[uplink_group.uplinks]]` entry the same way the
/// startup loader would. Used by `/control/uplinks` CRUD endpoints to
/// reject invalid payloads before writing them to the config file.
#[cfg(feature = "control")]
pub(crate) fn validate_uplink_section(
    section: &UplinkSection,
    index: usize,
) -> Result<UplinkConfig> {
    ResolvedUplinkInput::from_section(index, section).try_into()
}

fn cli_uplink_override_requested(args: &Args) -> bool {
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
