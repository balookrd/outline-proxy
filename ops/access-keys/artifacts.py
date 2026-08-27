#!/usr/bin/env python3
"""Assemble per-user artifacts from the config model and the URI layer.

`legacy_artifacts` reproduces what the binary writes — one file per artifact.
Nothing writes those files any more; the function exists so equivalence can be
proven, both by the golden test and by the node-side comparison during rollout.
The shipped layout is three files per user, built from the same pieces.
"""

from __future__ import annotations

from dataclasses import dataclass

import outline_yaml
import uri
import ws_toml
from config_model import AccessKeys, Endpoint, ServerConfig, User, endpoints_of_kind


@dataclass(frozen=True)
class Artifact:
    name: str
    content: str


def config_url(user: User, ak: AccessKeys) -> str | None:
    if not ak.url_base or user.password is None:
        return None
    return uri.join_url(ak.url_base, f"{user.filename}{ak.file_extension}")


def outline_url(user: User, ak: AccessKeys) -> str | None:
    """The `ssconf://` link an Outline client is given.

    Same file as `config_url`, different scheme: Outline follows it as a
    dynamic access key and re-reads the config when it changes.
    """
    url = config_url(user, ak)
    return uri.ssconf_url(url) if url else None


def has_subscription(user: User, server: ServerConfig) -> bool:
    """Whether this user gets a <user>.json — a VLESS id plus a VLESS endpoint."""
    return bool(user.vless_id) and bool(endpoints_of_kind(server, "ws_vless", "xhttp_vless"))


def happ_url(user: User, server: ServerConfig) -> str | None:
    """The link handed to xray-family clients: the Xray-JSON subscription.

    Always `.json` — `file_extension` applies to the Outline artifact only.
    """
    ak = server.access_keys
    if not ak.url_base or not has_subscription(user, server):
        return None
    return uri.join_url(ak.url_base, f"{user.filename}.json")


def ws_url(user: User, server: ServerConfig) -> str | None:
    """The link handed to the Android client: the ws-rust config.

    Always `.toml` — `file_extension` applies to the Outline artifact only.
    """
    ak = server.access_keys
    if not ak.url_base or not ws_toml.has_wires(user, server):
        return None
    return uri.join_url(ak.url_base, f"{user.filename}.toml")


def _outline_legs(server: ServerConfig) -> tuple[Endpoint | None, Endpoint | None]:
    """The first split SS-over-WS TCP and UDP legs, the pair Outline rides.

    Outline is a plain third-party client: it cannot do combined SS or padding,
    so it dials the split legs (`ws_ss_tcp` / `ws_ss_udp`), which operators keep
    plain. Their `padded` flag is not consulted here.
    """
    tcp = endpoints_of_kind(server, "ws_ss_tcp")
    udp = endpoints_of_kind(server, "ws_ss_udp")
    return (tcp[0] if tcp else None, udp[0] if udp else None)


def has_outline(user: User, server: ServerConfig) -> bool:
    """Whether this user gets a <user>.conf — a password plus both split legs.

    Outline needs both the TCP and the UDP leg; without either the artifact is
    not emitted, and neither is the ssconf link that would point at it.
    """
    tcp, udp = _outline_legs(server)
    return user.password is not None and tcp is not None and udp is not None


def outline_artifact(user: User, server: ServerConfig) -> str | None:
    if user.password is None:
        return None
    tcp, udp = _outline_legs(server)
    if tcp is None or udp is None:
        return None
    ak = server.access_keys
    return outline_yaml.render(
        user.method,
        user.password,
        outline_yaml.websocket_url(ak.public_scheme, ak.public_host, tcp.path),
        outline_yaml.websocket_url(ak.public_scheme, ak.public_host, udp.path),
    )


def legacy_artifacts(user: User, server: ServerConfig) -> list[Artifact]:
    """Every artifact the binary emits for this user, in the binary's order.

    One share link per combined SS (`ws_ss` / `xhttp_ss`) and VLESS
    (`ws_vless` / `xhttp_vless`) endpoint the user's credential unlocks, in the
    fixed carrier order the old per-user paths produced. Padding does not enter
    here: the `.txt` lists every carrier, padded or plain.
    """
    out: list[Artifact] = []
    ak = server.access_keys
    host, scheme, has_h3 = ak.public_host, ak.public_scheme, server.alpn_has_h3

    outline = outline_artifact(user, server)
    if outline is not None:
        out.append(Artifact(user.filename, outline))

    if user.password is not None:
        for endpoint in endpoints_of_kind(server, "ws_ss"):
            out.append(
                Artifact(
                    f"{user.filename}-ss-ws",
                    uri.ss_ws_uri(
                        user.method,
                        user.password,
                        host,
                        scheme,
                        endpoint.path,
                        user.name,
                        uri.alpn_list(scheme, has_h3, "ws"),
                    )
                    + "\n",
                )
            )
        for endpoint in endpoints_of_kind(server, "xhttp_ss"):
            for mode in ("packet-up", "stream-one"):
                out.append(
                    Artifact(
                        f"{user.filename}-ss-xhttp-{mode}",
                        uri.ss_xhttp_uri(
                            user.method,
                            user.password,
                            host,
                            scheme,
                            endpoint.path,
                            user.name,
                            mode,
                            uri.alpn_list(scheme, has_h3, mode),
                        )
                        + "\n",
                    )
                )

    if user.vless_id is not None:
        for endpoint in endpoints_of_kind(server, "ws_vless"):
            out.append(
                Artifact(
                    f"{user.filename}-vless-ws",
                    uri.vless_ws_uri(
                        user.vless_id,
                        host,
                        scheme,
                        endpoint.path,
                        user.name,
                        uri.alpn_list(scheme, has_h3, "ws"),
                    )
                    + "\n",
                )
            )
        for endpoint in endpoints_of_kind(server, "xhttp_vless"):
            for mode in ("packet-up", "stream-one"):
                out.append(
                    Artifact(
                        f"{user.filename}-vless-xhttp-{mode}",
                        uri.vless_xhttp_uri(
                            user.vless_id,
                            host,
                            scheme,
                            endpoint.path,
                            user.name,
                            mode,
                            uri.alpn_list(scheme, has_h3, mode),
                        )
                        + "\n",
                    )
                )

    return out


def user_urls(user: User, server: ServerConfig) -> list[str]:
    """Lines of <user>.txt: the ssconf link, then every URI in artifact order.

    Built by repackaging `legacy_artifacts` rather than re-rendering, so the two
    can never drift. The ssconf line leads only when the Outline `.conf` is
    actually emitted (password + both split legs).
    """
    lines: list[str] = []
    if has_outline(user, server):
        ssconf = outline_url(user, server.access_keys)
        if ssconf:
            lines.append(ssconf)
    lines.extend(
        artifact.content.rstrip("\n")
        for artifact in legacy_artifacts(user, server)
        if artifact.content.startswith(("ss://", "vless://"))
    )
    return lines
