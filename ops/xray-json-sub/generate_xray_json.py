#!/usr/bin/env python3
"""Build Xray-JSON subscriptions that balance across the cloud entry nodes.

Reads the authoritative outline-ss-rust config.toml on an entry node and emits
one <user>.json per VLESS-capable user, next to the .conf access keys.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class User:
    name: str
    vless_id: str


@dataclass(frozen=True)
class ServerConfig:
    xhttp_path: str
    ws_path: str
    users: tuple[User, ...]


def load_server_config(path: str | Path) -> ServerConfig:
    """Parse config.toml into the subset the subscription needs.

    Users without a `vless_id` are Shadowsocks-only and are skipped with a
    warning; a missing VLESS path is fatal, since every outbound needs it.
    """
    with open(path, "rb") as handle:
        raw = tomllib.load(handle)

    websocket = raw.get("websocket", {})
    xhttp_path = websocket.get("xhttp_path_vless")
    ws_path = websocket.get("ws_path_vless")
    if not xhttp_path or not ws_path:
        raise SystemExit(
            f"{path}: [websocket] must define both xhttp_path_vless and ws_path_vless"
        )

    users: list[User] = []
    for entry in raw.get("users", []):
        name = entry.get("id")
        vless_id = entry.get("vless_id")
        if not name:
            continue
        if not vless_id:
            print(f"skip {name}: no vless_id", file=sys.stderr)
            continue
        users.append(User(name=name, vless_id=vless_id))

    return ServerConfig(xhttp_path=xhttp_path, ws_path=ws_path, users=tuple(users))


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
    vless_id: str, xhttp_path: str, ws_path: str, nodes: Sequence[str]
) -> list[dict]:
    """Six proxy legs across two axes — node and transport — then direct/block.

    ALPN is a selector in xray, not a preference list: a leg gets exactly one
    value. h3 rides QUIC, h2 rides TCP, and the WS legs must stay on http/1.1
    because xray's wsSettings speaks plain HTTP/1.1 Upgrade only (no RFC 8441),
    even though outline-ss-rust would accept Extended CONNECT.
    """
    proxies: list[dict] = []

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


def build_config(user: User, server: ServerConfig, nodes: Sequence[str]) -> dict:
    """One complete Xray config for a single user."""
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
            user.vless_id, server.xhttp_path, server.ws_path, nodes
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


DEFAULT_CONFIG = "/opt/outline/outline-ss-rust/config.toml"
DEFAULT_OUT_DIR = "/var/www/html/<keys-prefix>"


def write_subscription(out_dir: Path, user: User, document: dict) -> Path:
    """Write <user>.json atomically so a client never reads a half file."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{user.name}.json"
    tmp = out_dir / f".{user.name}.json.tmp"

    payload = json.dumps([document], indent=2, ensure_ascii=False) + "\n"
    tmp.write_text(payload, encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, target)
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Xray-JSON subscriptions with a cloud balancer."
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG, help="outline-ss-rust config.toml"
    )
    parser.add_argument(
        "--out-dir", default=DEFAULT_OUT_DIR, help="where <user>.json is written"
    )
    parser.add_argument(
        "--node",
        action="append",
        dest="nodes",
        help="entry node hostname; repeat for each. Default: %s"
        % ", ".join(DEFAULT_NODES),
    )
    args = parser.parse_args(argv)

    nodes = tuple(args.nodes) if args.nodes else DEFAULT_NODES
    server = load_server_config(args.config)
    if not server.users:
        raise SystemExit(f"{args.config}: no users with a vless_id")

    out_dir = Path(args.out_dir)
    for user in server.users:
        document = build_config(user, server, nodes)
        target = write_subscription(out_dir, user, document)
        # Never the vless_id: file names and counts only.
        print(f"wrote {target}")

    print(f"{len(server.users)} subscription(s) across {len(nodes)} node(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
