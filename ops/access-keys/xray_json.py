#!/usr/bin/env python3
"""Build Xray-JSON subscriptions that balance across the cloud entry nodes.

Renders the document only. Config parsing lives in `config_model` and file
writing in `generate_keys`, so this module stays free of I/O.
"""

from __future__ import annotations

from collections.abc import Sequence

from config_model import User


DEFAULT_NODES: tuple[str, ...] = ("cloud1.beerloga.su", "cloud2.beerloga.su")
PORT = 443


def node_tag(node: str) -> str:
    """cloud1.beerloga.su -> cloud1. Also the balancer's selector prefix."""
    return node.split(".", 1)[0]


def _tls_settings(node: str, alpn: list[str]) -> dict:
    return {"serverName": node, "alpn": alpn, "fingerprint": "chrome"}


def _vless_outbound(tag: str, node: str, vless_id: str, stream: dict) -> dict:
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": node,
                    "port": PORT,
                    "users": [{"id": vless_id, "encryption": "none", "level": 0}],
                }
            ]
        },
        "streamSettings": stream,
    }


def build_outbounds(
    vless_id: str,
    xhttp_path: str | None,
    ws_path: str | None,
    nodes: Sequence[str],
) -> list[dict]:
    """Six proxy legs across two axes — node and transport — then direct/block.

    ALPN is a selector in xray, not a preference list: a leg gets exactly one
    value. h3 rides QUIC, h2 rides TCP, and the WS legs must stay on http/1.1
    because xray's wsSettings speaks plain HTTP/1.1 Upgrade only (no RFC 8441),
    even though outline-ss-rust would accept Extended CONNECT.

    A path of None drops its transport rather than emitting a leg that dials
    nothing: a user configured for only one carrier gets a smaller balancer,
    not a broken one.
    """
    proxies: list[dict] = []

    if xhttp_path:
        for alpn, suffix in (("h3", "xhttp-h3"), ("h2", "xhttp-h2")):
            for node in nodes:
                proxies.append(
                    _vless_outbound(
                        f"{node_tag(node)}-{suffix}",
                        node,
                        vless_id,
                        {
                            "network": "xhttp",
                            "security": "tls",
                            "tlsSettings": _tls_settings(node, [alpn]),
                            "xhttpSettings": {
                                "path": xhttp_path,
                                "host": node,
                                "mode": "stream-one",
                            },
                        },
                    )
                )

    if ws_path:
        for node in nodes:
            proxies.append(
                _vless_outbound(
                    f"{node_tag(node)}-ws",
                    node,
                    vless_id,
                    {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": _tls_settings(node, ["http/1.1"]),
                        "wsSettings": {"path": ws_path, "host": node},
                    },
                )
            )

    # INVARIANT: direct/block stay last. A leastPing balancer falls back to
    # outbounds[0] until the first observatory probe lands, so a `direct` in
    # that slot would leak the first ~30s of traffic outside the tunnel.
    return proxies + [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ]


BALANCER_TAG = "cloud-balancer"
PING_DESTINATION = "https://www.gstatic.com/generate_204"

# Spelled out rather than `geoip:private`: in JSON mode Happ decides which
# fragments of the geo databases reach the core, and this must not depend on
# that. Covers unspecified, RFC 1918, CGNAT, loopback, link-local, multicast
# and broadcast, plus the IPv6 equivalents.
PRIVATE_CIDRS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


def build_config(user: User, nodes: Sequence[str]) -> dict:
    """One complete Xray config for a single user, using that user's paths."""
    selector = [f"{node_tag(node)}-" for node in nodes]

    return {
        "remarks": f"{user.name} cloud-balancer",
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "settings": {"auth": "noauth", "udp": True},
                # Without sniffing the TUN hands the core a locally resolved
                # IP and the domain never reaches the server.
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": False,
                },
            },
            {
                "tag": "http-in",
                "protocol": "http",
                "listen": "127.0.0.1",
                "port": 10809,
            },
        ],
        "outbounds": build_outbounds(
            user.vless_id, user.xhttp_path_vless, user.ws_path_vless, nodes
        ),
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": BALANCER_TAG},
            ],
            "balancers": [
                {
                    "tag": BALANCER_TAG,
                    "selector": selector,
                    "strategy": {"type": "leastPing"},
                }
            ],
        },
        # Probes ride the outbound they measure, so they cover the whole path
        # entry -> exit -> internet, not just the entry node being up.
        "burstObservatory": {
            "subjectSelector": selector,
            "pingConfig": {
                "destination": PING_DESTINATION,
                "interval": "30s",
                "timeout": "5s",
                "sampling": 3,
            },
        },
    }


