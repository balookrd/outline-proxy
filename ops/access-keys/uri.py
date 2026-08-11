#!/usr/bin/env python3
"""URI construction for access-key artifacts.

Byte-for-byte equivalent to `config/access_key.rs`. No file I/O lives here so
the whole layer can be checked against the golden corpus.
"""

from __future__ import annotations

import base64
import ipaddress

_QUERY_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_FRAGMENT_SAFE = _QUERY_SAFE | {":"}


def _percent_encode(value: str, safe: frozenset[str] | set[str]) -> str:
    out: list[str] = []
    for byte in value.encode("utf-8"):
        ch = chr(byte)
        if ch in safe:
            out.append(ch)
        else:
            out.append(f"%{byte:02X}")  # uppercase hex, as in Rust
    return "".join(out)


def percent_encode_query_value(value: str) -> str:
    return _percent_encode(value, _QUERY_SAFE)


def percent_encode_fragment(value: str) -> str:
    return _percent_encode(value, _FRAGMENT_SAFE)


def normalize_path(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"


def normalize_host(host: str) -> str:
    """Bracket a bare IPv6 literal; leave anything else alone."""
    if host.startswith("[") or ":" not in host:
        return host
    addr, _, port = host.rpartition(":")
    if port.isdigit():
        try:
            ipaddress.IPv6Address(addr)
        except ValueError:
            pass
        else:
            return f"[{addr}]:{port}"
    return f"[{host}]"


def _strip_host_port(host: str) -> str:
    if host.startswith("["):
        closing = host.find("]")
        return host[1:closing] if closing != -1 else host[1:]
    head, sep, tail = host.rpartition(":")
    return head if sep and tail.isdigit() else host


def authority_with_default_port(host: str, default_port: int) -> str:
    normalized = normalize_host(host)
    if normalized.startswith("["):
        return normalized if "]:" in normalized else f"{normalized}:{default_port}"
    head, sep, tail = normalized.rpartition(":")
    if sep and tail.isdigit():
        return normalized
    return f"{normalized}:{default_port}"


def host_short_label(host: str) -> str:
    raw = _strip_host_port(host)
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        head, sep, _ = raw.partition(".")
        return head if sep else raw
    return raw


def carrier_label(host: str, user_id: str, transport: str) -> str:
    return f"{host_short_label(host)}:{user_id}-{transport}"


def join_url(base: str, suffix: str) -> str:
    if not (base.startswith("https://") or base.startswith("http://")):
        raise ValueError("url_base must start with http:// or https://")
    return f"{base.rstrip('/')}/{suffix}"


def ssconf_url(config_url: str) -> str:
    for scheme in ("https://", "http://"):
        if config_url.startswith(scheme):
            return f"ssconf://{config_url[len(scheme):]}"
    if config_url.startswith("ssconf://"):
        return config_url
    raise ValueError("config URL must start with http://, https:// or ssconf://")


def ss_userinfo(method: str, password: str) -> str:
    """SIP002 userinfo: url-safe base64 of `method:password`, no padding."""
    raw = f"{method}:{password}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def yaml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def alpn_list(scheme: str, has_h3: bool, carrier: str) -> str | None:
    """Comma-separated ALPN preference list, or None for plain HTTP.

    `http/1.1` is the universal floor for WS and XHTTP packet-up. stream-one
    omits it: h1 cannot full-duplex, so the server answers 505 and a client
    that picked h1 bounces on every dial.
    """
    if scheme != "wss":
        return None
    entries = ["h3"] if has_h3 else []
    entries.append("h2")
    if carrier in ("ws", "packet-up"):
        entries.append("http/1.1")
    return ",".join(entries)


def _security(scheme: str) -> str:
    return "tls" if scheme == "wss" else "none"


def _default_port(scheme: str) -> int:
    return 443 if scheme == "wss" else 80


def _alpn_segment(alpn: str | None) -> str:
    return f"&alpn={percent_encode_query_value(alpn)}" if alpn else ""


def vless_ws_uri(
    vless_id: str, host: str, scheme: str, path: str, label: str, alpn: str | None
) -> str:
    fragment = carrier_label(host, label, "vless-ws")
    return (
        f"vless://{vless_id}@{authority_with_default_port(host, _default_port(scheme))}"
        f"?type=ws&security={_security(scheme)}{_alpn_segment(alpn)}"
        f"&path={percent_encode_query_value(normalize_path(path))}"
        f"&encryption=none#{percent_encode_fragment(fragment)}"
    )


def vless_xhttp_uri(
    vless_id: str,
    host: str,
    scheme: str,
    path: str,
    label: str,
    mode: str,
    alpn: str | None,
) -> str:
    fragment = carrier_label(host, label, f"vless-xhttp-{mode}")
    return (
        f"vless://{vless_id}@{authority_with_default_port(host, _default_port(scheme))}"
        f"?type=xhttp&mode={mode}&security={_security(scheme)}{_alpn_segment(alpn)}"
        f"&path={percent_encode_query_value(normalize_path(path))}"
        f"&encryption=none#{percent_encode_fragment(fragment)}"
    )


def ss_ws_uri(
    method: str,
    password: str,
    host: str,
    scheme: str,
    path: str,
    label: str,
    alpn: str | None,
) -> str:
    fragment = carrier_label(host, label, "ss-ws")
    return (
        f"ss://{ss_userinfo(method, password)}"
        f"@{authority_with_default_port(host, _default_port(scheme))}"
        f"?type=ws&security={_security(scheme)}{_alpn_segment(alpn)}"
        f"&path={percent_encode_query_value(normalize_path(path))}"
        f"#{percent_encode_fragment(fragment)}"
    )


def ss_xhttp_uri(
    method: str,
    password: str,
    host: str,
    scheme: str,
    path: str,
    label: str,
    mode: str,
    alpn: str | None,
) -> str:
    fragment = carrier_label(host, label, f"ss-xhttp-{mode}")
    return (
        f"ss://{ss_userinfo(method, password)}"
        f"@{authority_with_default_port(host, _default_port(scheme))}"
        f"?type=xhttp&mode={mode}&security={_security(scheme)}{_alpn_segment(alpn)}"
        f"&path={percent_encode_query_value(normalize_path(path))}"
        f"#{percent_encode_fragment(fragment)}"
    )
