use std::collections::{HashMap, HashSet};

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
            carrier_downgrade,
        } = input;

        let weight = weight.unwrap_or(1.0);
        if !weight.is_finite() || weight <= 0.0 {
            bail!("uplink weight must be a finite positive number");
        }
        let shuffle_wires = shuffle_wires.unwrap_or(false);
        // Default is `true` (legacy `h3 → h2 → h1` cascade preserved). The
        // operator opts out by setting `carrier_downgrade = false` in
        // `[[outline.uplinks]]` when intermediate ranks are useless on
        // this uplink and the operator wants failures to jump straight
        // to the next wire (or the next uplink) without spending the
        // `mode_downgrade_secs` window per rank.
        let carrier_downgrade = carrier_downgrade.unwrap_or(true);

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
            carrier_downgrade,
        };

        let fallbacks = resolve_fallbacks(&parent, &input_fallbacks)?;
        // The shuffle itself is no longer applied here. `load_uplinks`
        // runs a per-group pass after every uplink has been resolved,
        // so a wire chain `[primary, fallbacks…]` can be reshuffled
        // with awareness of the orderings already assigned to other
        // uplinks in the same group. Doing the shuffle here would
        // produce statistical collisions (≈ 44% probability of two
        // 3-wire uplinks landing on the same permutation under
        // independent `thread_rng()` samples), defeating the operator
        // intent of "different wires on different uplinks".
        Ok(UplinkConfig { fallbacks, ..parent })
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
/// Apply `permutation` (a complete permutation of `0..total_wires`) to
/// the uplink's wire chain in place. The permutation `[2, 0, 1]` means
/// "the new wire-0 is the original wire-2, the new wire-1 is the
/// original wire-0, the new wire-2 is the original wire-1".
///
/// Caller must check `uplink.shuffle_wires` and `!uplink.fallbacks.is_empty()`
/// before invoking, and supply a `permutation` of length `1 +
/// uplink.fallbacks.len()`.
fn apply_wire_permutation(uplink: &mut UplinkConfig, permutation: &[usize]) {
    let mut chain: Vec<FallbackTransport> = Vec::with_capacity(1 + uplink.fallbacks.len());
    chain.push(primary_to_fallback_shape(uplink));
    chain.append(&mut uplink.fallbacks);

    let permuted: Vec<FallbackTransport> = permutation.iter().map(|&i| chain[i].clone()).collect();
    let mut iter = permuted.into_iter();
    let new_primary = iter
        .next()
        .expect("permutation must be non-empty when shuffle_wires + fallbacks non-empty");
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

    // Per-section group label captured here so the post-resolve shuffle
    // pass can dedupe permutations within the same group. `UplinkConfig`
    // itself does not carry the group — it is attached later by the
    // registry — so we keep the labels in a parallel vector during the
    // loading pipeline.
    let group_labels: Vec<Option<String>> = uplinks.iter().map(|u| u.group.clone()).collect();
    let mut resolved: Vec<UplinkConfig> = uplinks
        .iter()
        .enumerate()
        .map(|(index, uplink)| ResolvedUplinkInput::from_section(index, uplink).try_into())
        .collect::<Result<_>>()?;
    shuffle_wire_chains_per_group(&mut resolved, &group_labels);
    Ok(resolved)
}

/// Walk every uplink that has `shuffle_wires = true`, group them by their
/// `[[outline.uplinks]].group` label, and assign each one a random
/// permutation of its wire chain that does **not** collide with the
/// permutations already given to other uplinks in the same group.
///
/// Why this matters: an independent `rand::thread_rng()` shuffle per
/// uplink would give two 3-wire uplinks in the same group a ≈ 44%
/// chance of landing on the same `[primary, fallback, fallback]`
/// ordering at process start, even though both ran through
/// `SliceRandom::shuffle` cleanly. That is statistical noise, not a
/// bug, but it defeats the operator intent ("each uplink takes a
/// different starting wire so the group as a whole spreads load
/// across CDN edges / mirror hosts / etc."). This pass spends a few
/// re-rolls per uplink to maximise distinctness in cases where it is
/// physically possible — for `N` uplinks in a group sharing a
/// `total_wires`-wire chain, all `N` orderings can be distinct only
/// while `N ≤ total_wires!`, and we honour that cap.
///
/// Permutations are tracked per group as `Vec<usize>` keys; when a
/// candidate matches one already used in the same group, the
/// permutation is re-rolled up to [`SHUFFLE_DEDUP_ATTEMPTS`] times,
/// after which the last roll is accepted (preserving randomness
/// rather than blocking startup on a tiny carrier-chain space).
pub(in crate::config::load) fn shuffle_wire_chains_per_group(
    uplinks: &mut [UplinkConfig],
    group_labels: &[Option<String>],
) {
    debug_assert_eq!(uplinks.len(), group_labels.len());
    let mut seen_per_group: HashMap<String, HashSet<Vec<usize>>> = HashMap::new();
    let mut rng = rand::thread_rng();
    for (i, uplink) in uplinks.iter_mut().enumerate() {
        if !uplink.shuffle_wires || uplink.fallbacks.is_empty() {
            continue;
        }
        let total_wires = 1 + uplink.fallbacks.len();
        // Group key: same fallback for missing `group` as the registry's
        // implicit `default` so an unlabelled group still shares
        // collision tracking across its members.
        let group_key = group_labels[i].clone().unwrap_or_else(|| "default".to_string());
        let seen = seen_per_group.entry(group_key).or_default();
        let mut permutation: Vec<usize> = (0..total_wires).collect();
        let mut attempt = 0u32;
        loop {
            permutation.shuffle(&mut rng);
            // Collision-free in the group, OR we burnt the attempt
            // budget — accept either way.
            if !seen.contains(&permutation) || attempt >= SHUFFLE_DEDUP_ATTEMPTS {
                break;
            }
            attempt += 1;
        }
        seen.insert(permutation.clone());
        apply_wire_permutation(uplink, &permutation);
    }
}

/// Maximum re-rolls per uplink when its first shuffled permutation
/// collides with one already used in the same group. 32 covers the
/// realistic chain depths (3–4 wires → 6–24 distinct permutations);
/// past that the group is large enough that some collisions are
/// physically unavoidable and falling back to the latest roll is
/// honest.
const SHUFFLE_DEDUP_ATTEMPTS: u32 = 32;

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
