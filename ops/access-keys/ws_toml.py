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
from config_model import ServerConfig, User

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

    `path` is the server-side carrier path this link dials. It is kept beside
    the link because the padding decision needs it: the client's `[padding]`
    switch is global, so it may only be turned on when every path in the chain
    is one the server pads.
    """

    link: str
    path: str


def build_wires(user: User, node: str, scheme: str, has_h3: bool) -> list[Wire]:
    """The uplink's carrier chain for one node, best carrier first.

    Order is fixed and deliberate: xhttp stream-one rides QUIC full-duplex and
    is our best carrier; ws is the same proxy protocol on a different carrier
    family; the SS wires are a different proxy protocol entirely, so they
    survive a block aimed at VLESS; packet-up is the most compatible and the
    most expensive, hence last resort.

    ALPN does not multiply wires the way it multiplies xray outbounds: ws-rust
    reads the first token as the requested mode and downgrades inside the wire
    (`ws_h3 -> ws_h2 -> ws_h1`).

    A missing path or credential drops its wire rather than emitting a link
    that dials nothing. Split SS (`ws_path_tcp` / `ws_path_udp`) has no share
    link at all — `ss://` only expands to the combined path — so it never
    joins the chain.
    """
    wires: list[Wire] = []

    if user.vless_id and user.xhttp_path_vless:
        wires.append(
            Wire(
                uri.vless_xhttp_uri(
                    user.vless_id,
                    node,
                    scheme,
                    user.xhttp_path_vless,
                    user.name,
                    "stream-one",
                    uri.alpn_list(scheme, has_h3, "stream-one"),
                ),
                user.xhttp_path_vless,
            )
        )

    if user.vless_id and user.ws_path_vless:
        wires.append(
            Wire(
                uri.vless_ws_uri(
                    user.vless_id,
                    node,
                    scheme,
                    user.ws_path_vless,
                    user.name,
                    uri.alpn_list(scheme, has_h3, "ws"),
                ),
                user.ws_path_vless,
            )
        )

    if user.password is not None and user.ws_path_ss:
        wires.append(
            Wire(
                uri.ss_ws_uri(
                    user.method,
                    user.password,
                    node,
                    scheme,
                    user.ws_path_ss,
                    user.name,
                    uri.alpn_list(scheme, has_h3, "ws"),
                ),
                user.ws_path_ss,
            )
        )

    if user.password is not None and user.xhttp_path_ss:
        wires.append(
            Wire(
                uri.ss_xhttp_uri(
                    user.method,
                    user.password,
                    node,
                    scheme,
                    user.xhttp_path_ss,
                    user.name,
                    "stream-one",
                    uri.alpn_list(scheme, has_h3, "stream-one"),
                ),
                user.xhttp_path_ss,
            )
        )

    if user.vless_id and user.xhttp_path_vless:
        wires.append(
            Wire(
                uri.vless_xhttp_uri(
                    user.vless_id,
                    node,
                    scheme,
                    user.xhttp_path_vless,
                    user.name,
                    "packet-up",
                    uri.alpn_list(scheme, has_h3, "packet-up"),
                ),
                user.xhttp_path_vless,
            )
        )

    return wires


def has_wires(user: User) -> bool:
    """Whether this user gets a <user>.toml at all.

    Asks `build_wires` rather than repeating its conditions, so the predicate
    and the chain can never disagree about who is dialable. The node and
    scheme only shape the links, not whether any exist.
    """
    return bool(build_wires(user, "node.invalid", "wss", has_h3=True))


def quote(value: str) -> str:
    """TOML basic string. `tomllib` only reads, so the writer is ours."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def node_name(node: str) -> str:
    """cloud1.beerloga.su -> cloud1. Also the uplink's name."""
    return node.split(".", 1)[0]


def _chain_paths(user: User, nodes: Sequence[str], server: ServerConfig) -> set[str]:
    scheme = server.access_keys.public_scheme
    return {
        wire.path
        for node in nodes
        for wire in build_wires(user, node, scheme, server.alpn_has_h3)
    }


def pads_every_wire(user: User, nodes: Sequence[str], server: ServerConfig) -> bool:
    """Whether the client may switch carrier padding on.

    The client knob is global — there is no per-wire override — and padding is
    config-synchronised rather than negotiated. Padding a path the server
    serves plain feeds padded frames into its plain decoder and kills the
    session, so partial coverage means the whole switch stays off.
    """
    if not server.padding.enabled:
        return False
    paths = _chain_paths(user, nodes, server)
    return bool(paths) and paths.issubset(set(server.padding.paths))


def config_warnings(user: User, nodes: Sequence[str], server: ServerConfig) -> list[str]:
    """What this node's config costs the generated client, in plain text.

    Each line names a server-side switch that is off and the behaviour the
    client loses because of it. Paths only — never a credential.
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

    if server.padding.enabled and not pads_every_wire(user, nodes, server):
        missing = sorted(_chain_paths(user, nodes, server) - set(server.padding.paths))
        out.append(
            "padding stays off: the node pads only some of this user's carrier paths; "
            "unpadded " + ", ".join(missing)
        )

    return out


def build_config(user: User, nodes: Sequence[str], server: ServerConfig) -> str | None:
    """One complete ws-rust config for a single user, or None if undialable.

    Section order is not cosmetic: `[[outline.uplinks.fallbacks]]` binds to the
    `[[outline.uplinks]]` above it, so every flat section is written first and
    the uplinks come last.
    """
    scheme = server.access_keys.public_scheme
    chains = [(node, build_wires(user, node, scheme, server.alpn_has_h3)) for node in nodes]
    chains = [(node, wires) for node, wires in chains if wires]
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
        f"enabled = {str(pads_every_wire(user, nodes, server)).lower()}",
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
