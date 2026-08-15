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
from config_model import AccessKeys, User


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


def has_subscription(user: User) -> bool:
    """Whether this user gets a <user>.json — a VLESS id plus a path to reach."""
    return bool(user.vless_id) and bool(user.ws_path_vless or user.xhttp_path_vless)


def happ_url(user: User, ak: AccessKeys) -> str | None:
    """The link handed to xray-family clients: the Xray-JSON subscription.

    Always `.json` — `file_extension` applies to the Outline artifact only.
    """
    if not ak.url_base or not has_subscription(user):
        return None
    return uri.join_url(ak.url_base, f"{user.filename}.json")


def ws_url(user: User, ak: AccessKeys) -> str | None:
    """The link handed to the Android client: the ws-rust config.

    Always `.toml` — `file_extension` applies to the Outline artifact only.
    """
    if not ak.url_base or not ws_toml.has_wires(user):
        return None
    return uri.join_url(ak.url_base, f"{user.filename}.toml")


def outline_artifact(user: User, ak: AccessKeys) -> str | None:
    if user.password is None:
        return None
    return outline_yaml.render(
        user.method,
        user.password,
        outline_yaml.websocket_url(ak.public_scheme, ak.public_host, user.ws_path_tcp),
        outline_yaml.websocket_url(ak.public_scheme, ak.public_host, user.ws_path_udp),
    )


def legacy_artifacts(user: User, ak: AccessKeys, has_h3: bool) -> list[Artifact]:
    """Every artifact the binary emits for this user, in the binary's order."""
    out: list[Artifact] = []
    host, scheme = ak.public_host, ak.public_scheme

    outline = outline_artifact(user, ak)
    if outline is not None:
        out.append(Artifact(user.filename, outline))

    if user.password is not None:
        if user.ws_path_ss:
            out.append(
                Artifact(
                    f"{user.filename}-ss-ws",
                    uri.ss_ws_uri(
                        user.method,
                        user.password,
                        host,
                        scheme,
                        user.ws_path_ss,
                        user.name,
                        uri.alpn_list(scheme, has_h3, "ws"),
                    )
                    + "\n",
                )
            )
        if user.xhttp_path_ss:
            for mode in ("packet-up", "stream-one"):
                out.append(
                    Artifact(
                        f"{user.filename}-ss-xhttp-{mode}",
                        uri.ss_xhttp_uri(
                            user.method,
                            user.password,
                            host,
                            scheme,
                            user.xhttp_path_ss,
                            user.name,
                            mode,
                            uri.alpn_list(scheme, has_h3, mode),
                        )
                        + "\n",
                    )
                )

    if user.vless_id is not None:
        if user.ws_path_vless:
            out.append(
                Artifact(
                    f"{user.filename}-vless-ws",
                    uri.vless_ws_uri(
                        user.vless_id,
                        host,
                        scheme,
                        user.ws_path_vless,
                        user.name,
                        uri.alpn_list(scheme, has_h3, "ws"),
                    )
                    + "\n",
                )
            )
        if user.xhttp_path_vless:
            for mode in ("packet-up", "stream-one"):
                out.append(
                    Artifact(
                        f"{user.filename}-vless-xhttp-{mode}",
                        uri.vless_xhttp_uri(
                            user.vless_id,
                            host,
                            scheme,
                            user.xhttp_path_vless,
                            user.name,
                            mode,
                            uri.alpn_list(scheme, has_h3, mode),
                        )
                        + "\n",
                    )
                )

    return out


def user_urls(user: User, ak: AccessKeys, has_h3: bool) -> list[str]:
    """Lines of <user>.txt: the ssconf link, then every URI in artifact order.

    Built by repackaging `legacy_artifacts` rather than re-rendering, so the two
    can never drift.
    """
    lines: list[str] = []
    ssconf = outline_url(user, ak)
    if ssconf:
        lines.append(ssconf)
    lines.extend(
        artifact.content.rstrip("\n")
        for artifact in legacy_artifacts(user, ak, has_h3)
        if artifact.content.startswith(("ss://", "vless://"))
    )
    return lines
