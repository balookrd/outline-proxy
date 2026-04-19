use anyhow::{Context, Result, anyhow, bail};
use url::Url;

use outline_transport::{ServerAddr, WsTransportMode};
use outline_uplink::{UplinkConfig, UplinkTransport};
use shadowsocks_crypto::CipherKind;

use super::super::args::Args;
use super::super::schema::{OutlineSection, UplinkSection};

#[derive(Debug, Clone)]
pub(super) struct ResolvedUplinkInput {
    pub(super) name: String,
    pub(super) transport: UplinkTransport,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_ws_mode: Option<WsTransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_ws_mode: Option<WsTransportMode>,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) cipher: Option<CipherKind>,
    pub(super) password: Option<String>,
    pub(super) weight: Option<f64>,
    pub(super) fwmark: Option<u32>,
    pub(super) ipv6_first: Option<bool>,
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
            tcp_addr: uplink.tcp_addr.clone(),
            udp_addr: uplink.udp_addr.clone(),
            cipher: uplink.method,
            password: uplink.password.clone(),
            weight: uplink.weight,
            fwmark: uplink.fwmark,
            ipv6_first: uplink.ipv6_first,
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
            tcp_addr,
            udp_addr,
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first,
        } = input;

        let weight = weight.unwrap_or(1.0);
        if !weight.is_finite() || weight <= 0.0 {
            bail!("uplink weight must be a finite positive number");
        }
        let cipher = cipher.unwrap_or(CipherKind::Chacha20IetfPoly1305);
        let password = password
            .ok_or_else(|| anyhow!("missing password: set it in config.toml or pass --password"))?;
        cipher
            .derive_master_key(&password)
            .with_context(|| format!("invalid password/PSK for cipher {cipher}"))?;

        Ok(UplinkConfig {
            name,
            transport,
            tcp_ws_url: match transport {
                UplinkTransport::Websocket => Some(tcp_ws_url.ok_or_else(|| {
                    anyhow!("missing tcp_ws_url: set it in config.toml or pass --tcp-ws-url")
                })?),
                UplinkTransport::Shadowsocks => {
                    if tcp_ws_url.is_some() || udp_ws_url.is_some() {
                        bail!(
                            "websocket uplink fields are not valid for transport=shadowsocks; use tcp_addr/udp_addr"
                        );
                    }
                    None
                },
            },
            tcp_ws_mode: tcp_ws_mode.unwrap_or_default(),
            udp_ws_url: match transport {
                UplinkTransport::Websocket => udp_ws_url,
                UplinkTransport::Shadowsocks => None,
            },
            udp_ws_mode: udp_ws_mode.unwrap_or_default(),
            tcp_addr: match transport {
                UplinkTransport::Websocket => {
                    if tcp_addr.is_some() || udp_addr.is_some() {
                        bail!(
                            "socket uplink fields are not valid for transport=websocket; use tcp_ws_url/udp_ws_url"
                        );
                    }
                    None
                },
                UplinkTransport::Shadowsocks => Some(tcp_addr.ok_or_else(|| {
                    anyhow!("missing tcp_addr: set it in config.toml or pass --tcp-addr")
                })?),
            },
            udp_addr: match transport {
                UplinkTransport::Websocket => None,
                UplinkTransport::Shadowsocks => udp_addr,
            },
            cipher,
            password,
            weight,
            fwmark,
            ipv6_first: ipv6_first.unwrap_or(false),
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

fn cli_uplink_override_requested(args: &Args) -> bool {
    args.tcp_ws_url.is_some()
        || args.transport.is_some()
        || args.tcp_ws_mode.is_some()
        || args.udp_ws_url.is_some()
        || args.udp_ws_mode.is_some()
        || args.tcp_addr.is_some()
        || args.udp_addr.is_some()
        || args.method.is_some()
        || args.password.is_some()
        || args.fwmark.is_some()
        || args.ipv6_first.is_some()
}
