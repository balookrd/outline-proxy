#!/usr/bin/env python3
"""Parse an outline-ss-rust config.toml into what the access-key artifacts need.

Every fallback here mirrors the Rust side: `UserEntry::effective_*` for the
per-user overrides, `Config::h3_enabled` + `effective_h3_listen` for the ALPN
decision. Getting one of them wrong produces artifacts that look right and dial
a path the server does not serve.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

DEFAULT_METHOD = "chacha20-ietf-poly1305"
DEFAULT_SCHEME = "wss"
DEFAULT_EXTENSION = ".yaml"

# nginx serves the artifacts from here on every node in the fleet
# (`root /var/www/html` in sites-available/default), which is what makes a
# URL path derivable from `write_dir` at all.
NGINX_DOCUMENT_ROOT = "/var/www/html"


@dataclass(frozen=True)
class AccessKeys:
    """The `[access_keys]` fields the artifacts are built from.

    `write_dir` is where the artifacts land. It is the same key the binary's
    `--write-access-keys-dir` mode reads, so the node's config.toml is the one
    place naming that directory. It stays out of this repository on purpose:
    the served directory is unguessable-by-design and its name is the only
    thing standing between the internet and every user's credentials.

    `print` is deliberately absent: it gated an extra stdout report in the
    binary, the generator has no such report, and carrying a field nothing
    reads only invites someone to believe it does something.
    """

    public_host: str
    public_scheme: str
    url_base: str | None
    file_extension: str
    write_dir: str | None


@dataclass(frozen=True)
class User:
    name: str
    filename: str
    password: str | None
    method: str
    vless_id: str | None
    ws_path_tcp: str
    ws_path_udp: str
    ws_path_vless: str | None
    ws_path_ss: str | None
    xhttp_path_vless: str | None
    xhttp_path_ss: str | None


@dataclass(frozen=True)
class Padding:
    """The server's `[padding]` block.

    Carrier padding is config-synchronised, not negotiated on the wire: a
    server that does not pad a path feeds padded frames to its plain decoder
    and the session dies. `paths` is therefore the exact set the client may
    turn padding on for.
    """

    enabled: bool
    paths: tuple[str, ...]


@dataclass(frozen=True)
class SessionResumption:
    """The server's `[session_resumption]` block.

    `enabled` mints the Session IDs a client's carrier migration re-attaches
    to; without it the client-side knob is inert. `downlink_buffer_bytes` is
    the v2 Symmetric Downlink Replay ring — at 0 only the uplink gap is
    replayed and a migrated download keeps a hole where the downstream bytes
    were.
    """

    enabled: bool
    downlink_buffer_bytes: int


@dataclass(frozen=True)
class ServerConfig:
    access_keys: AccessKeys
    users: tuple[User, ...]
    alpn_has_h3: bool
    padding: Padding = Padding(enabled=False, paths=())
    session_resumption: SessionResumption = SessionResumption(
        enabled=False, downlink_buffer_bytes=0
    )
    cluster_enabled: bool = False


def sanitize_filename(value: str) -> str:
    """Mirrors `sanitize_filename` in access_key.rs."""
    out = "".join(
        ch if (ch.isascii() and (ch.isalnum() or ch in "._-")) else "_" for ch in value
    )
    return out or "user"


def _h3_in_alpn(server: dict) -> bool:
    """True when the URI should advertise h3.

    Rust: `effective_h3_listen().is_some()`, i.e. h3 is enabled AND has a listen
    address. Enabled means a default cert pair (h3's own, else the TCP one) or a
    non-empty cert array — where the h3 array inherits the TCP array only when
    the key is absent entirely; an explicit `certs = []` opts out.
    """
    h3 = server.get("h3", {})
    if h3.get("listen") is None:
        return False

    tcp_cert = server.get("cert_path") or server.get("tls_cert_path")
    tcp_key = server.get("key_path") or server.get("tls_key_path")
    cert_path = h3.get("cert_path") or tcp_cert
    key_path = h3.get("key_path") or tcp_key
    if cert_path and key_path:
        return True

    certs = h3["certs"] if "certs" in h3 else server.get("certs", [])
    return bool(certs)


def _derive_url_base(public_host: str, public_scheme: str, write_dir: str | None) -> str | None:
    """Where clients fetch the artifacts from, when the config does not say.

    The URL path is `write_dir` taken relative to the nginx document root, so
    a nested directory keeps its whole path: `/var/www/html/keys/prod` becomes
    `/keys/prod`, not `/prod`. The scheme follows the transport one — `wss` is
    served over https, `ws` over http.

    A `write_dir` outside the document root derives nothing. The URL path
    simply is not knowable from a filesystem path in that case, and inventing
    one would fail the worst way available here: artifacts written correctly,
    with links inside them pointing at a directory that does not exist. Such a
    deployment must spell `url_base` out.
    """
    if not write_dir:
        return None
    try:
        relative = PurePosixPath(write_dir.rstrip("/")).relative_to(NGINX_DOCUMENT_ROOT)
    except ValueError:
        return None
    if not relative.parts:
        return None
    scheme = "https" if public_scheme == "wss" else "http"
    return f"{scheme}://{public_host}/{relative}"


def load(path: str | Path) -> ServerConfig:
    with open(path, "rb") as handle:
        raw = tomllib.load(handle)

    server = raw.get("server", {})
    websocket = raw.get("websocket", {})
    ak_section = raw.get("access_keys", {})

    public_host = ak_section.get("public_host")
    if not public_host:
        raise SystemExit(f"{path}: [access_keys] public_host is required")

    public_scheme = ak_section.get("public_scheme") or DEFAULT_SCHEME
    if public_scheme not in ("ws", "wss"):
        raise SystemExit(f'{path}: public_scheme must be either "ws" or "wss"')

    write_dir = ak_section.get("write_dir")
    access_keys = AccessKeys(
        public_host=public_host,
        public_scheme=public_scheme,
        url_base=ak_section.get("url_base") or _derive_url_base(public_host, public_scheme, write_dir),
        file_extension=ak_section.get("file_extension") or DEFAULT_EXTENSION,
        write_dir=write_dir,
    )

    default_method = raw.get("shadowsocks", {}).get("method") or DEFAULT_METHOD

    users: list[User] = []
    seen: set[str] = set()
    for entry in raw.get("users", []):
        name = entry.get("id")
        if not name:
            continue
        if name in seen:
            raise SystemExit(f"{path}: duplicate user id {name!r}")
        seen.add(name)
        if not entry.get("enabled", True):
            continue
        if entry.get("password") is None and entry.get("vless_id") is None:
            continue

        users.append(
            User(
                name=name,
                filename=sanitize_filename(name),
                password=entry.get("password"),
                method=entry.get("method") or default_method,
                vless_id=entry.get("vless_id"),
                ws_path_tcp=entry.get("ws_path_tcp") or websocket.get("ws_path_tcp", ""),
                ws_path_udp=entry.get("ws_path_udp") or websocket.get("ws_path_udp", ""),
                ws_path_vless=entry.get("ws_path_vless") or websocket.get("ws_path_vless"),
                ws_path_ss=entry.get("ws_path_ss") or websocket.get("ws_path_ss"),
                xhttp_path_vless=entry.get("xhttp_path_vless")
                or websocket.get("xhttp_path_vless"),
                xhttp_path_ss=entry.get("xhttp_path_ss") or websocket.get("xhttp_path_ss"),
            )
        )

    padding_section = raw.get("padding", {})
    resumption_section = raw.get("session_resumption", {})

    return ServerConfig(
        access_keys=access_keys,
        users=tuple(users),
        alpn_has_h3=_h3_in_alpn(server),
        padding=Padding(
            enabled=bool(padding_section.get("enabled", False)),
            paths=tuple(padding_section.get("paths", ())),
        ),
        session_resumption=SessionResumption(
            enabled=bool(resumption_section.get("enabled", False)),
            downlink_buffer_bytes=int(resumption_section.get("downlink_buffer_bytes", 0)),
        ),
        # Absent or false means standalone: the mesh listener never starts and
        # session ids stay plain random, so a group cannot share resumption.
        cluster_enabled=bool(raw.get("cluster", {}).get("enabled", False)),
    )
