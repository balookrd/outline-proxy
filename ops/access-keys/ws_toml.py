#!/usr/bin/env python3
"""Build an outline-ws-rust client config for the Android app.

Renders the document only. Config parsing lives in `config_model` and file
writing in `generate_keys`, so this module stays free of I/O — the same split
`xray_json` follows.

Every wire is a share link built by `uri`, byte-for-byte the same links that
go into <user>.txt: credentials ride inside the URI, so the uplink needs no
`method` / `password` / `vless_id` of its own, and the two forms cannot drift.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

import uri
from config_model import ServerConfig, User, endpoints_of_kind

PORT = 443
GROUP = "main"
TUN_MTU = 1500  # MUST match ServerProfile.TUN_MTU / VpnService.Builder.setMtu
RESELECT_INTERVAL = "6h"

# Reshuffle each uplink's wire chain once at load so the primary is not always
# the same carrier shape.
SHUFFLE_WIRES = True
# When the chain is shuffled, also reroll the *active* wire on a timer picked
# in this closed range of minutes. Bounds only — the exact per-uplink value is
# a stable hash of identity, see shuffle_timer().
# Probe settings, mirroring the `main` group on cloud1 — the phone needs the
# same health signal the fleet clients have. Without any `[probe]` section at
# all (the shape this generator used to emit) `healthy` is written only by the
# data path, so a client that loses every uplink at once — a SIM switch, a dead
# cell — has no independent way to find out they came back, and the UI has no
# latency to show either: the RTT the status displays comes from probe samples
# and real dials alike, but on a phone the dials are the only ones and they stop
# happening once everything is marked down.
#
# The one deliberate departure from cloud1 is the interval. The fleet probes
# every 10 s from mains power over a fat pipe; a phone would pay for that in
# battery and — on the edge-class cells this whole exercise is about — in the
# very bandwidth the tunnel needs. 60 s is the floor ws-rust itself recommends
# (below it, bursts of handshakes trip upstream rate limits), and it still finds
# a recovered uplink inside a minute without any traffic to prompt it.
PROBE_INTERVAL_SECS = 60
PROBE_TIMEOUT_SECS = 10
# Two consecutive failures before a verdict: one probe cycle can lose to a
# handover or a moment of congestion, which on mobile is normal rather than a
# reason to fail over.
PROBE_MIN_FAILURES = 2
# One handshake per cycle. `min_failures` already absorbs a flap, so a second
# attempt would only double the cost of every cycle.
PROBE_ATTEMPTS = 1
# Bare-TCP reachability sweep across every wire, run only after a cycle has
# already failed on all of them: a switched-off exit is then called down at once
# instead of walking the carrier descent for minutes.
PROBE_ENDPOINT_CHECK = True
PROBE_ENDPOINT_CHECK_TIMEOUT_MS = 2000
PROBE_DNS_SERVER = "1.1.1.1"
PROBE_DNS_PORT = 53
PROBE_DNS_NAME = "google.com"
# TLS handshakes through the tunnel, same targets as cloud1: hosts that are
# both unremarkable to reach and representative of what the user actually
# opens, so a probe passing means something a user would notice.
PROBE_TLS_TARGETS = (
    "www.instagram.com",
    "www.youtube.com",
    "www.googletagmanager.com",
    "www.googlevideo.com",
    "api.telegram.org",
)

SHUFFLE_TIMER_MIN_MINUTES = 30
SHUFFLE_TIMER_MAX_MINUTES = 60


def shuffle_timer(user: User, node: str) -> str:
    """Per-uplink active-wire reroll interval, a stable pick in [30, 60] minutes.

    Not a constant: a fixed reroll period is itself a fingerprint, so every
    user/node uplink gets its own cadence. The value is derived by hashing
    identity (sha256 — not Python's per-process-salted `hash`) rather than drawn
    fresh each run, so regeneration stays idempotent and the golden corpus stays
    byte-for-byte: a client's config never churns on a re-run, yet two clients
    rarely share a period. Parsed by the same human-duration reader as
    reselect_interval, so `"43m"` is 2580s.
    """
    span = SHUFFLE_TIMER_MAX_MINUTES - SHUFFLE_TIMER_MIN_MINUTES + 1
    digest = hashlib.sha256(f"{user.name}\x00{node}".encode()).digest()
    minutes = SHUFFLE_TIMER_MIN_MINUTES + int.from_bytes(digest[:8], "big") % span
    return f"{minutes}m"


@dataclass(frozen=True)
class Wire:
    """One dialable carrier of an uplink.

    `path` is the server-side carrier path this link dials, kept beside the link
    for the padding warnings. `padded` is the endpoint's own flag: the client's
    `[padding]` switch is global, so the chain is filtered to a single padding
    class (see `padding_enabled`) rather than mixing padded and plain wires.
    """

    link: str
    path: str
    padded: bool


def build_wires(user: User, node: str, server: ServerConfig) -> list[Wire]:
    """The uplink's carrier chain for one node, best carrier first.

    One `Wire` per matching endpoint, in a fixed carrier order: xhttp stream-one
    rides QUIC full-duplex and is our best carrier; ws is the same proxy
    protocol on a different carrier family; the SS wires are a different proxy
    protocol entirely, so they survive a block aimed at VLESS; packet-up is the
    most compatible and the most expensive, hence last resort.

    Carriers come from the server's `[[endpoint]]` list: VLESS kinds need
    `user.vless_id`, SS kinds need `user.password`. Combined SS (`ws_ss` /
    `xhttp_ss`) and VLESS (`ws_vless` / `xhttp_vless`) endpoints join the chain;
    the split SS legs (`ws_ss_tcp` / `ws_ss_udp`) have no share link — `ss://`
    only expands to a combined path — so they never do. Each wire carries its
    endpoint's `padded` flag.

    ALPN does not multiply wires the way it multiplies xray outbounds: ws-rust
    reads the first token as the requested mode and downgrades inside the wire
    (`ws_h3 -> ws_h2 -> ws_h1`).
    """
    scheme = server.access_keys.public_scheme
    has_h3 = server.alpn_has_h3
    wires: list[Wire] = []

    if user.vless_id:
        for endpoint in endpoints_of_kind(server, "xhttp_vless"):
            wires.append(
                Wire(
                    uri.vless_xhttp_uri(
                        user.vless_id,
                        node,
                        scheme,
                        endpoint.path,
                        user.name,
                        "stream-one",
                        uri.alpn_list(scheme, has_h3, "stream-one"),
                    ),
                    endpoint.path,
                    endpoint.padded,
                )
            )

    if user.vless_id:
        for endpoint in endpoints_of_kind(server, "ws_vless"):
            wires.append(
                Wire(
                    uri.vless_ws_uri(
                        user.vless_id,
                        node,
                        scheme,
                        endpoint.path,
                        user.name,
                        uri.alpn_list(scheme, has_h3, "ws"),
                    ),
                    endpoint.path,
                    endpoint.padded,
                )
            )

    if user.password is not None:
        for endpoint in endpoints_of_kind(server, "ws_ss"):
            wires.append(
                Wire(
                    uri.ss_ws_uri(
                        user.method,
                        user.password,
                        node,
                        scheme,
                        endpoint.path,
                        user.name,
                        uri.alpn_list(scheme, has_h3, "ws"),
                    ),
                    endpoint.path,
                    endpoint.padded,
                )
            )

    if user.password is not None:
        for endpoint in endpoints_of_kind(server, "xhttp_ss"):
            wires.append(
                Wire(
                    uri.ss_xhttp_uri(
                        user.method,
                        user.password,
                        node,
                        scheme,
                        endpoint.path,
                        user.name,
                        "stream-one",
                        uri.alpn_list(scheme, has_h3, "stream-one"),
                    ),
                    endpoint.path,
                    endpoint.padded,
                )
            )

    if user.vless_id:
        for endpoint in endpoints_of_kind(server, "xhttp_vless"):
            wires.append(
                Wire(
                    uri.vless_xhttp_uri(
                        user.vless_id,
                        node,
                        scheme,
                        endpoint.path,
                        user.name,
                        "packet-up",
                        uri.alpn_list(scheme, has_h3, "packet-up"),
                    ),
                    endpoint.path,
                    endpoint.padded,
                )
            )

    return wires


def has_wires(user: User, server: ServerConfig) -> bool:
    """Whether this user gets a <user>.toml at all.

    Asks `build_wires` rather than repeating its conditions, so the predicate
    and the chain can never disagree about who is dialable. The node only shapes
    the links, not whether any exist.
    """
    return bool(build_wires(user, "node.invalid", server))


def quote(value: str) -> str:
    """TOML basic string. `tomllib` only reads, so the writer is ours."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def node_name(node: str) -> str:
    """cloud1.beerloga.su -> cloud1. Also the uplink's name."""
    return node.split(".", 1)[0]


def padding_enabled(user: User, server: ServerConfig) -> bool:
    """Whether the generated client turns carrier padding on.

    "Only padded, if any": when any wire the user could dial is padded, the
    client keeps only the padded wires (see `build_config`) and switches padding
    on; otherwise every wire is plain and the switch stays off. The client
    `[padding]` knob is global — no per-wire override — and padding is
    config-synchronised rather than negotiated, so a chain must never mix padded
    and plain carriers.

    Padded-ness is a property of the server's endpoints, identical across nodes,
    so a single synthetic node answers it.
    """
    return any(wire.padded for wire in build_wires(user, "node.invalid", server))


def config_warnings(user: User, server: ServerConfig) -> list[str]:
    """What this node's config costs the generated client, in plain text.

    Each line names a server-side switch and the behaviour it changes for the
    client. Paths only — never a credential.
    """
    out: list[str] = []

    if not server.session_resumption.enabled:
        out.append(
            "carrier migration is inert: the node has no [session_resumption] "
            "enabled, so a flow whose carrier dies is torn down instead of migrating"
        )
    elif server.session_resumption.downlink_buffer_bytes == 0:
        out.append(
            "downstream replay is off: [session_resumption] downlink_buffer_bytes = 0, "
            "so a migrated download keeps a hole where the downstream bytes were "
            "(set 65536 to match the client ring)"
        )

    if not server.cluster_enabled:
        out.append(
            "switching the active uplink will reset live sessions: the node has no "
            "[cluster] enabled, so the group cannot share a resumption id and the "
            "switch cannot be soft"
        )

    if padding_enabled(user, server):
        dropped = sorted(
            {wire.path for wire in build_wires(user, "node.invalid", server) if not wire.padded}
        )
        if dropped:
            out.append(
                "carrier padding is on, so the plain fallbacks were dropped to keep the "
                "chain one padding class: excluded " + ", ".join(dropped)
            )

    return out


def build_config(user: User, nodes: Sequence[str], server: ServerConfig) -> str | None:
    """One complete ws-rust config for a single user, or None if undialable.

    Section order is not cosmetic: `[[outline.uplinks.fallbacks]]` binds to the
    `[[outline.uplinks]]` above it, so every flat section is written first and
    the uplinks come last.
    """
    pad = padding_enabled(user, server)
    chains: list[tuple[str, list[Wire]]] = []
    for node in nodes:
        wires = build_wires(user, node, server)
        # Global client switch: a padded chain drops its plain fallbacks so the
        # server's padded and plain decoders are never crossed.
        if pad:
            wires = [wire for wire in wires if wire.padded]
        if wires:
            chains.append((node, wires))
    if not chains:
        return None

    lines: list[str] = [
        "# outline-ws-rust client config for the Android app.",
        f"# Generated for user {user.name} — do not edit by hand.",
        "",
        "[tun]",
        # The descriptor itself comes from VpnService via RunOptions.tun_fd;
        # a non-empty path is what makes the loader activate TUN at all.
        'path = "vpn"',
        f"mtu = {TUN_MTU}",
        "",
        "[tun.tcp]",
        # The exit node must resolve the domain, so it has to reach it: without
        # sniffing the TUN hands the core a locally resolved IP.
        "sniffing = true",
        # Inert unless the server mints Session IDs, so it is safe either way.
        "carrier_migration = true",
        "",
        "[padding]",
        f"enabled = {str(pad).lower()}",
        "",
        "[[uplink_group]]",
        f"name = {quote(GROUP)}",
        # One node carries everything, so the egress IP stays put and
        # source-IP-bound logic on the far side does not break.
        'mode = "active_passive"',
        'routing_scope = "global"',
        # True only for a cluster mesh: it turns an uplink switch into a soft
        # migration of live sessions instead of an RST.
        f"shared_resume = {str(server.cluster_enabled).lower()}",
        f"reselect_interval = {quote(RESELECT_INTERVAL)}",
        # Without this every TUN dial goes to wire 0 and the fallback chain
        # below is decoration. Android is TUN, so it is mandatory here.
        "tun_wire_dial = true",
        "health_weighted_selection = true",
        "warm_standby_tcp = 1",
        "warm_standby_udp = 1",
        "",
        "[outline.probe]",
        f"interval_secs = {PROBE_INTERVAL_SECS}",
        f"timeout_secs = {PROBE_TIMEOUT_SECS}",
        f"min_failures = {PROBE_MIN_FAILURES}",
        f"attempts = {PROBE_ATTEMPTS}",
        f"endpoint_check = {str(PROBE_ENDPOINT_CHECK).lower()}",
        f"endpoint_check_timeout_ms = {PROBE_ENDPOINT_CHECK_TIMEOUT_MS}",
        "",
        "[outline.probe.dns]",
        f"server = {quote(PROBE_DNS_SERVER)}",
        f"port = {PROBE_DNS_PORT}",
        f"name = {quote(PROBE_DNS_NAME)}",
        "",
        "[outline.probe.tls]",
        "targets = [",
        *[f"  {quote(target)}," for target in PROBE_TLS_TARGETS],
        "]",
        "",
    ]

    for node, wires in chains:
        primary, fallbacks = wires[0], wires[1:]
        lines.extend(
            [
                "[[outline.uplinks]]",
                f"name = {quote(node_name(node))}",
                f"group = {quote(GROUP)}",
                "weight = 1.0",
                # Anti-DPI reroll across the idle wires of this uplink.
                f"shuffle_wires = {str(SHUFFLE_WIRES).lower()}",
                # Timed active-wire reroll rides on the shuffle being on.
                *([f"shuffle_timer = {quote(shuffle_timer(user, node))}"] if SHUFFLE_WIRES else []),
                f"link = {quote(primary.link)}",
                "",
            ]
        )
        for wire in fallbacks:
            lines.extend(
                [
                    "  [[outline.uplinks.fallbacks]]",
                    f"  link = {quote(wire.link)}",
                    "",
                ]
            )

    return "\n".join(lines).rstrip("\n") + "\n"
