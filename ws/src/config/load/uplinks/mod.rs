use anyhow::{Result, anyhow, bail};

use outline_uplink::UplinkConfig;

use super::super::args::Args;
use super::super::schema::{OutlineSection, UplinkSection};

mod credentials;
mod fallback_resolution;
mod source_precedence;
mod wire_shape;

use credentials::resolve_primary_credentials;
use fallback_resolution::resolve_fallbacks;
pub(super) use source_precedence::{ResolvedUplinkInput, cli_uplink_override_requested};
use wire_shape::{PrimaryWireInput, resolve_primary_wire_shape};

impl TryFrom<ResolvedUplinkInput> for UplinkConfig {
    type Error = anyhow::Error;

    fn try_from(input: ResolvedUplinkInput) -> Result<Self> {
        let input_fallbacks = input.fallbacks.clone();
        let ResolvedUplinkInput {
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
            ipv6_first,
            vless_id,
            link,
            fingerprint_profile,
            fallbacks: _,
        } = input;

        let weight = weight.unwrap_or(1.0);
        if !weight.is_finite() || weight <= 0.0 {
            bail!("uplink weight must be a finite positive number");
        }

        let wire = resolve_primary_wire_shape(PrimaryWireInput {
            name: &name,
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
            link,
        })?;
        let credentials =
            resolve_primary_credentials(&name, wire.transport, cipher, password, wire.vless_id)?;

        let parent = UplinkConfig {
            name,
            transport: wire.transport,
            tcp_ws_url: wire.tcp_ws_url,
            tcp_mode: wire.tcp_mode,
            udp_ws_url: wire.udp_ws_url,
            udp_mode: wire.udp_mode,
            vless_ws_url: wire.vless_ws_url,
            vless_xhttp_url: wire.vless_xhttp_url,
            vless_mode: wire.vless_mode,
            tcp_addr: wire.tcp_addr,
            udp_addr: wire.udp_addr,
            cipher: credentials.cipher,
            password: credentials.password,
            weight,
            fwmark,
            ipv6_first: ipv6_first.unwrap_or(false),
            vless_id: credentials.vless_id,
            fingerprint_profile,
            fallbacks: Vec::new(),
        };

        let fallbacks = resolve_fallbacks(&parent, &input_fallbacks)?;
        Ok(UplinkConfig { fallbacks, ..parent })
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
