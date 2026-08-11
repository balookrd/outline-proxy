#!/usr/bin/env python3
"""The Outline client artifact — the one artifact that is not a URI."""

from __future__ import annotations

from uri import normalize_host, normalize_path, yaml_quote


def websocket_url(scheme: str, host: str, path: str) -> str:
    return f"{scheme}://{normalize_host(host)}{normalize_path(path)}"


def render(method: str, password: str, tcp_url: str, udp_url: str) -> str:
    cipher = yaml_quote(method)
    secret = yaml_quote(password)
    return (
        "transport:\n"
        "  $type: tcpudp\n"
        "  tcp:\n"
        "    $type: shadowsocks\n"
        "    endpoint:\n"
        "      $type: websocket\n"
        f"      url: {yaml_quote(tcp_url)}\n"
        f"    cipher: {cipher}\n"
        f"    secret: {secret}\n"
        "  udp:\n"
        "    $type: shadowsocks\n"
        "    endpoint:\n"
        "      $type: websocket\n"
        f"      url: {yaml_quote(udp_url)}\n"
        f"    cipher: {cipher}\n"
        f"    secret: {secret}\n"
    )
