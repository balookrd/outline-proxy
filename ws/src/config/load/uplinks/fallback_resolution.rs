use anyhow::{anyhow, bail, Result};

use outline_transport::TransportMode;
use outline_uplink::{FallbackTransport, UplinkConfig, UplinkTransport};

use crate::config::schema::FallbackSection;

use super::credentials::{parse_vless_id, validate_shared_secret};

pub(super) fn resolve_fallbacks(
    parent: &UplinkConfig,
    sections: &[FallbackSection],
) -> Result<Vec<FallbackTransport>> {
    // Per-fallback validation runs against the now-resolved primary so error
    // messages can refer to the parent's `name`. Duplicate `transport`
    // entries are intentionally NOT rejected: a VLESS primary configured for
    // `xhttp_h*` may legitimately have a VLESS fallback configured for
    // `ws_h*`, and operators may also want multiple SS fallback hosts.
    let mut fallbacks = Vec::with_capacity(sections.len());
    for (idx, section) in sections.iter().enumerate() {
        fallbacks.push(resolve_fallback(parent, section, idx)?);
    }
    Ok(fallbacks)
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

    // Same-transport-as-parent fallbacks are explicitly allowed: the most
    // common shape is a VLESS primary on `xhttp_h*` falling back to a
    // *different VLESS endpoint* on `ws_h*` — same `transport = "vless"`,
    // different carrier family, different dial URL, different (or same)
    // vless_id. The dial loop's per-wire state machine and per-wire
    // mode-downgrade tracking treat each fallback entry as its own wire
    // regardless of the `transport` field, so cross-family fallbacks within
    // the same transport family work without special-casing.

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
            validate_shared_secret(cipher, &password_inherited, || {
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
            if matches!(mode, TransportMode::XhttpH3 | TransportMode::WsH3 | TransportMode::Quic) {
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
            let parsed_id = parse_vless_id(raw, || {
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
            validate_shared_secret(cipher, &password_inherited, || {
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
