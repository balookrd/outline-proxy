//! One carrier's dial shape, projected out of whichever wire is being dialed.
//!
//! A wire is not an uplink. It carries its own transport family, URL, mode and
//! credentials, but it shares the parent's identity — name, weight, group — for
//! scoring, metrics and logging. This projection is what lets one dial path
//! serve the primary carrier and every fallback without reading
//! `candidate.uplink` directly: a dial path that reads the uplink cannot help
//! but target the primary, which is how the TUN ingress ended up unable to use
//! fallback wires at all.
//!
//! Padding is deliberately absent: it is configured per uplink
//! (`UplinkConfig::padding`), not per wire, so the padding scope stays wrapped
//! around the parent by the callers. The TLS fingerprint strategy *is* here and
//! *is* read: the TCP dial and the warm-pool refill scope it through
//! [`crate::dial::dial_in_wire_scope`]. A fallback that omits the key inherits
//! the parent's at config-load time, so carrying it per wire changes nothing
//! for an uplink whose fallbacks say nothing about fingerprints.

use url::Url;

use crate::config::{
    CipherKind, FallbackTransport, SsPathKind, TransportMode, UplinkConfig, UplinkTransport,
};

/// Which plane a dial is for. `WireSpec` holds both planes' URLs and modes
/// because one wire can serve both (VLESS muxes them; combined-SS shares one
/// URL), and the caller picks per dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Tcp,
    Udp,
}

/// The dial shape of a single wire. Borrowed from the config it projects, so it
/// is cheap to build per dial and never clones credentials.
#[derive(Clone, Copy, Debug)]
pub struct WireSpec<'a> {
    /// Parent uplink's display name — the same for every wire on it.
    pub name: &'a str,
    /// `0` for the primary carrier, `i` for `fallbacks[i - 1]`.
    pub wire: u8,
    pub transport: UplinkTransport,
    pub cipher: CipherKind,
    pub password: &'a str,
    pub vless_id: Option<[u8; 16]>,
    pub fwmark: Option<u32>,
    pub ipv6_first: bool,
    pub fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
    tcp_url: Option<&'a Url>,
    udp_url: Option<&'a Url>,
    tcp_mode: TransportMode,
    udp_mode: TransportMode,
    combined_ss: bool,
}

impl<'a> WireSpec<'a> {
    /// Project the primary carrier — wire `0`.
    pub fn from_uplink(uplink: &'a UplinkConfig) -> Self {
        Self {
            name: &uplink.name,
            wire: 0,
            transport: uplink.transport,
            cipher: uplink.cipher,
            password: &uplink.password,
            vless_id: uplink.vless_id,
            fwmark: uplink.fwmark,
            ipv6_first: uplink.ipv6_first,
            fingerprint_profile: uplink.fingerprint_profile,
            tcp_url: uplink.tcp_dial_url(),
            udp_url: uplink.udp_dial_url(),
            tcp_mode: uplink.tcp_dial_mode(),
            udp_mode: uplink.udp_dial_mode(),
            combined_ss: uplink.is_combined_ss(),
        }
    }

    /// Project `fallbacks[wire - 1]`. `parent_name` is the uplink's name: a
    /// fallback shares its parent's identity everywhere except the wire shape.
    pub fn from_fallback(parent_name: &'a str, wire: u8, fallback: &'a FallbackTransport) -> Self {
        Self {
            name: parent_name,
            wire,
            transport: fallback.transport,
            cipher: fallback.cipher,
            password: &fallback.password,
            vless_id: fallback.vless_id,
            fwmark: fallback.fwmark,
            ipv6_first: fallback.ipv6_first,
            fingerprint_profile: fallback.fingerprint_profile,
            tcp_url: fallback.tcp_dial_url(),
            udp_url: fallback.udp_dial_url(),
            tcp_mode: fallback.tcp_dial_mode(),
            udp_mode: fallback.udp_dial_mode(),
            combined_ss: fallback.is_combined_ss(),
        }
    }

    /// Project wire `wire` of `uplink`: `0` is the primary, anything else
    /// indexes `fallbacks`. `None` when the index is past the end.
    pub fn of(uplink: &'a UplinkConfig, wire: u8) -> Option<Self> {
        if wire == 0 {
            return Some(Self::from_uplink(uplink));
        }
        let fallback = uplink.fallbacks.get((wire - 1) as usize)?;
        Some(Self::from_fallback(&uplink.name, wire, fallback))
    }

    pub fn dial_url(&self, plane: Plane) -> Option<&'a Url> {
        match plane {
            Plane::Tcp => self.tcp_url,
            Plane::Udp => self.udp_url,
        }
    }

    pub fn dial_mode(&self, plane: Plane) -> TransportMode {
        match plane {
            Plane::Tcp => self.tcp_mode,
            Plane::Udp => self.udp_mode,
        }
    }

    /// The combined-SS discriminator for `leg`, or `None` when this wire uses
    /// the default split paths. Taken from the wire, never from the parent: a
    /// pool filled with the other leg's streams silently drops every reused
    /// datagram.
    pub fn combined_ss_kind(&self, leg: SsPathKind) -> Option<SsPathKind> {
        self.combined_ss.then_some(leg)
    }

    /// Whether this wire has a UDP path configured at all.
    pub fn supports_udp(&self) -> bool {
        self.udp_url.is_some()
    }

    /// Whether this wire has a TCP path configured at all. The plane-symmetric
    /// twin of [`Self::supports_udp`]: both ingresses use it to tell "this wire
    /// is broken" apart from "this wire was never a candidate on this plane",
    /// which is the distinction the per-wire liveness weights are built on.
    pub fn supports_tcp(&self) -> bool {
        self.tcp_url.is_some()
    }

    /// Whether this wire's family can be dialed by the WS-family dial paths.
    pub fn is_ws_family(&self) -> bool {
        matches!(self.transport, UplinkTransport::Ss | UplinkTransport::Vless)
    }
}

#[cfg(test)]
#[path = "tests/wire_spec.rs"]
mod tests;
