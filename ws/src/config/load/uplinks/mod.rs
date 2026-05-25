use anyhow::{Result, anyhow, bail};
use rand::seq::SliceRandom;

use outline_uplink::{FallbackTransport, UplinkConfig};

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
            shuffle_wires,
        } = input;

        let weight = weight.unwrap_or(1.0);
        if !weight.is_finite() || weight <= 0.0 {
            bail!("uplink weight must be a finite positive number");
        }
        let shuffle_wires = shuffle_wires.unwrap_or(false);

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
            shuffle_wires,
        };

        let fallbacks = resolve_fallbacks(&parent, &input_fallbacks)?;
        let mut uplink = UplinkConfig { fallbacks, ..parent };
        if shuffle_wires && !uplink.fallbacks.is_empty() {
            shuffle_wire_chain(&mut uplink);
        }
        Ok(uplink)
    }
}

/// Randomly permute the wire chain `[primary, fallbacks[0], …]` in place.
///
/// The chain is materialised as a `Vec<FallbackTransport>` (each element
/// carries the wire-shape fields), shuffled with `rand::thread_rng()`,
/// and the first entry is folded back into the parent's primary slot
/// while the rest become the new `fallbacks` list. Parent-level identity
/// fields (`name`, `weight`, `fwmark`, `ipv6_first`, `fingerprint_profile`)
/// stay attached to the uplink regardless of which wire ended up at
/// position 0, so log lines, metrics, and per-uplink overrides remain
/// stable across restarts even as the dial ordering changes.
///
/// `fwmark` and `ipv6_first` are also wire-level fields on
/// `FallbackTransport` (they may differ per fallback after inheritance
/// at fallback-resolution time); we preserve each wire's own value so
/// a fallback that opted into a different fwmark / address family keeps
/// it when promoted to primary, and the parent's value rides along
/// only when this wire was the original primary.
///
/// Caller must check `uplink.shuffle_wires` and `!uplink.fallbacks.is_empty()`
/// before invoking.
fn shuffle_wire_chain(uplink: &mut UplinkConfig) {
    let mut chain: Vec<FallbackTransport> = Vec::with_capacity(1 + uplink.fallbacks.len());
    chain.push(primary_to_fallback_shape(uplink));
    chain.append(&mut uplink.fallbacks);

    chain.shuffle(&mut rand::thread_rng());

    let mut iter = chain.into_iter();
    let new_primary = iter
        .next()
        .expect("chain has at least 2 entries when shuffle_wires + fallbacks non-empty");
    apply_fallback_shape_to_primary(uplink, new_primary);
    uplink.fallbacks = iter.collect();
}

/// Extract the parent's wire-shape fields into a `FallbackTransport` so the
/// primary slot can participate in `shuffle_wire_chain`. Parent-level
/// identity (`name`, `weight`) is **not** captured here — it stays on the
/// `UplinkConfig` itself.
fn primary_to_fallback_shape(uplink: &UplinkConfig) -> FallbackTransport {
    FallbackTransport {
        transport: uplink.transport,
        tcp_ws_url: uplink.tcp_ws_url.clone(),
        tcp_mode: uplink.tcp_mode,
        udp_ws_url: uplink.udp_ws_url.clone(),
        udp_mode: uplink.udp_mode,
        vless_ws_url: uplink.vless_ws_url.clone(),
        vless_xhttp_url: uplink.vless_xhttp_url.clone(),
        vless_mode: uplink.vless_mode,
        vless_id: uplink.vless_id,
        tcp_addr: uplink.tcp_addr.clone(),
        udp_addr: uplink.udp_addr.clone(),
        cipher: uplink.cipher,
        password: uplink.password.clone(),
        fwmark: uplink.fwmark,
        ipv6_first: uplink.ipv6_first,
        fingerprint_profile: uplink.fingerprint_profile.clone(),
    }
}

/// Reverse of `primary_to_fallback_shape`: write a fallback's wire-shape
/// fields into the parent's primary slot. Used after the shuffle to install
/// whichever wire landed at chain[0] as the new primary.
fn apply_fallback_shape_to_primary(uplink: &mut UplinkConfig, wire: FallbackTransport) {
    uplink.transport = wire.transport;
    uplink.tcp_ws_url = wire.tcp_ws_url;
    uplink.tcp_mode = wire.tcp_mode;
    uplink.udp_ws_url = wire.udp_ws_url;
    uplink.udp_mode = wire.udp_mode;
    uplink.vless_ws_url = wire.vless_ws_url;
    uplink.vless_xhttp_url = wire.vless_xhttp_url;
    uplink.vless_mode = wire.vless_mode;
    uplink.vless_id = wire.vless_id;
    uplink.tcp_addr = wire.tcp_addr;
    uplink.udp_addr = wire.udp_addr;
    uplink.cipher = wire.cipher;
    uplink.password = wire.password;
    uplink.fwmark = wire.fwmark;
    uplink.ipv6_first = wire.ipv6_first;
    uplink.fingerprint_profile = wire.fingerprint_profile;
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

/// Validate a single `[[outline.uplinks]]` entry the same way the
/// startup loader would. Used by `/control/uplinks` CRUD endpoints to
/// reject invalid payloads before writing them to the config file.
#[cfg(feature = "control")]
pub(crate) fn validate_uplink_section(
    section: &UplinkSection,
    index: usize,
) -> Result<UplinkConfig> {
    ResolvedUplinkInput::from_section(index, section).try_into()
}
