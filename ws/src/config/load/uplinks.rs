use anyhow::{Context, Result, anyhow, bail};
use url::Url;

use outline_transport::{ServerAddr, TransportMode};
use outline_uplink::{UplinkConfig, UplinkTransport};
use shadowsocks_crypto::CipherKind;

use super::super::args::Args;
use super::super::schema::{OutlineSection, UplinkSection};

#[derive(Debug, Clone)]
pub(super) struct ResolvedUplinkInput {
    pub(super) name: String,
    pub(super) transport: UplinkTransport,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_ws_mode: Option<TransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_ws_mode: Option<TransportMode>,
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
}

impl ResolvedUplinkInput {
    pub(super) fn from_cli(args: &Args, outline: Option<&OutlineSection>) -> Self {
        Self {
            name: "cli".to_string(),
            transport: args
                .transport
                .or_else(|| outline.and_then(|section| section.transport))
                .unwrap_or_default(),
            tcp_ws_url: args
                .tcp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.tcp_ws_url.clone())),
            tcp_ws_mode: args
                .tcp_ws_mode
                .or_else(|| outline.and_then(|section| section.tcp_ws_mode)),
            udp_ws_url: args
                .udp_ws_url
                .clone()
                .or_else(|| outline.and_then(|section| section.udp_ws_url.clone())),
            udp_ws_mode: args
                .udp_ws_mode
                .or_else(|| outline.and_then(|section| section.udp_ws_mode)),
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
        }
    }

    pub(super) fn from_section(index: usize, uplink: &UplinkSection) -> Self {
        Self {
            name: uplink.name.clone().unwrap_or_else(|| format!("uplink-{}", index + 1)),
            transport: uplink.transport.unwrap_or_default(),
            tcp_ws_url: uplink.tcp_ws_url.clone(),
            tcp_ws_mode: uplink.tcp_ws_mode,
            udp_ws_url: uplink.udp_ws_url.clone(),
            udp_ws_mode: uplink.udp_ws_mode,
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
        }
    }

}

impl TryFrom<ResolvedUplinkInput> for UplinkConfig {
    type Error = anyhow::Error;

    fn try_from(input: ResolvedUplinkInput) -> Result<Self> {
        let ResolvedUplinkInput {
            name,
            transport,
            tcp_ws_url,
            tcp_ws_mode,
            udp_ws_url,
            udp_ws_mode,
            vless_ws_url,
            vless_xhttp_url,
            vless_mode,
            tcp_addr,
            udp_addr,
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first,
            vless_id,
        } = input;

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
            tcp_ws_mode,
            udp_ws_url,
            udp_ws_mode,
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
                        tcp_ws_mode.unwrap_or_default(),
                        udp_ws_url,
                        udp_ws_mode.unwrap_or_default(),
                        None,
                        None,
                        TransportMode::default(),
                        None,
                        None,
                    )
                },
                UplinkTransport::Vless => {
                    if tcp_ws_url.is_some()
                        || tcp_ws_mode.is_some()
                        || udp_ws_url.is_some()
                        || udp_ws_mode.is_some()
                    {
                        bail!(
                            "uplink {name}: `tcp_ws_url`/`tcp_ws_mode`/`udp_ws_url`/`udp_ws_mode` are not valid for transport=vless; use `vless_ws_url`/`vless_xhttp_url`/`vless_mode` instead (the VLESS server exposes a single path for both TCP and UDP)"
                        );
                    }
                    if tcp_addr.is_some() || udp_addr.is_some() {
                        bail!(
                            "uplink {name}: `tcp_addr`/`udp_addr` are only valid for transport=shadowsocks"
                        );
                    }
                    let mode = vless_mode.unwrap_or_default();
                    // Cross-check: the URL field carrying the dial target
                    // must match the chosen mode. Forgetting either is a
                    // common mistake; surface it as a clear error rather
                    // than a confusing dial-time failure.
                    let needs_xhttp_url =
                        matches!(mode, TransportMode::XhttpH2 | TransportMode::XhttpH3);
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
                        || tcp_ws_mode.is_some()
                        || udp_ws_url.is_some()
                        || udp_ws_mode.is_some()
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

        Ok(UplinkConfig {
            name,
            transport,
            tcp_ws_url,
            tcp_ws_mode,
            udp_ws_url,
            udp_ws_mode,
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
        })
    }
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
        || args.tcp_ws_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_ws_mode.is_some()
        || args.vless_ws_url.is_some()
        || args.vless_xhttp_url.is_some()
        || args.vless_mode.is_some()
        || args.tcp_addr.is_some()
        || args.udp_addr.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some()
        || args.ipv6_first.is_some()
}
