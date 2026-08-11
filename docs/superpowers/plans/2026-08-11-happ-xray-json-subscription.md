# Happ Xray-JSON subscription with a cloud1+cloud2 balancer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate a per-user Xray-JSON subscription that balances six VLESS
outbounds across `cloud1` and `cloud2`, so Happ clients fail over automatically
instead of being pinned to whichever node round-robin DNS handed them.

**Architecture:** A standalone Python 3 script reads the authoritative
`config.toml` on an entry node, and for every user with a `vless_id` writes
`<user>.json` next to the existing `.conf` access-key artifacts. The document is
a single-element array holding one full Xray config: six proxy outbounds
(`xhttp-h3`, `xhttp-h2`, `ws` × two nodes), a `leastPing` balancer fed by
`burstObservatory`, and routing that sends private CIDRs direct and everything
else to the balancer. Nothing in `outline-ss-rust` changes; delivery reuses the
static path nginx already serves.

**Tech Stack:** Python 3.12 stdlib only (`tomllib`, `json`, `argparse`,
`unittest`) — no third-party packages on the nodes, no pytest. Deployment is
`rsync` + `ssh`, matching the other `ops/` roles.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-08-11-happ-xray-json-subscription-design.md`. Every decision below traces to it.
- **Python floor:** 3.11 (`tomllib` is stdlib from 3.11). Nodes run 3.12.3; the dev Mac runs 3.14.5.
- **Stdlib only.** No `pip install` on cloud1/cloud2 — they are production entry nodes.
- **Outbound order is an invariant:** the six proxy legs come first, `direct` and `block` last. A `leastPing` balancer routes to the *first* outbound until the first observatory probe lands; `direct` in that slot leaks traffic outside the tunnel, silently.
- **ALPN values are exact:** `["h3"]` for the QUIC legs, `["h2"]` for the TCP-XHTTP legs, `["http/1.1"]` for the WS legs. `alpn` in xray is a selector, not a preference list — `["h3","h2"]` yields h2. xray's `wsSettings` cannot do RFC 8441, so a WS leg with `["h2"]` negotiates h2 and then attempts an h1 Upgrade, and the dial bounces.
- **Paths come from the node's own `config.toml`** (`[websocket] xhttp_path_vless`, `ws_path_vless`) — never hardcoded, they are secrets-by-obscurity and may rotate.
- **Never print `vless_id`, `password` or the control token to stdout/logs.** Per `AGENTS.md`: no secrets in logs.
- **Commits:** the repository rule is that `git commit` / `git push` run only on the owner's explicit instruction. Commit steps below are written out, but must not be executed until the owner says so.
- **Production:** cloud1 and cloud2 are live entry nodes. Deploy one node at a time. No service restarts are required by this change — do not restart anything.
- **Language:** code comments and commit messages in English; `ops/*/README.md` in Russian, matching `ops/watchdog/README.md` and `ops/heartbeat/README.md`.

---

## File Structure

| File | Responsibility |
|---|---|
| `ops/xray-json-sub/generate_xray_json.py` | Create. Parse `config.toml`, build the Xray document, write `<user>.json` atomically. Importable module name (underscores) so tests can load it. |
| `ops/xray-json-sub/test_generate_xray_json.py` | Create. `unittest` suite covering parsing, outbound shape/order, ALPN, routing, and atomic writes. Runs anywhere python3 ≥3.11 exists; touches nothing outside `tempfile`. |
| `ops/xray-json-sub/README.md` | Create. What it produces, how to run it, how to deploy, the outbound-order invariant, the client URL. |
| `/opt/outline/outline-ss-rust/save-keys.sh` (on both nodes) | Modify during rollout, not in the repo — append the generator call after the `.conf` generation. |

The generator stays one file: it is ~150 lines with three clear seams
(`load_server_config` → `build_config` → `write_subscription`), and splitting it
would spread a single data flow across imports for no gain.

---

### Task 1: Parse `config.toml` into users and paths

**Files:**
- Create: `ops/xray-json-sub/generate_xray_json.py`
- Test: `ops/xray-json-sub/test_generate_xray_json.py`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `User(name: str, vless_id: str)` and `ServerConfig(xhttp_path: str, ws_path: str, users: tuple[User, ...])`, both frozen dataclasses; `load_server_config(path: str | Path) -> ServerConfig`.

- [ ] **Step 1: Write the failing test**

Create `ops/xray-json-sub/test_generate_xray_json.py`:

```python
#!/usr/bin/env python3
"""Offline tests for generate_xray_json.py. Stdlib only; no network, no node access."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_xray_json as gen  # noqa: E402

# Trimmed to the keys the generator reads. Values are fake.
CONFIG_TOML = """
[server]
listen = "[::]:443"

[websocket]
ws_path_tcp = "/SECRET/tcp"
ws_path_vless = "/SECRET/vless"
xhttp_path_vless = "/OTHER/xhttp"

[[users]]
id = "alice"
password = "pw1"
vless_id = "11111111-1111-4111-8111-111111111111"

[[users]]
id = "bob"
password = "pw2"
vless_id = "22222222-2222-4222-8222-222222222222"

[[users]]
id = "legacy-ss-only"
password = "pw3"
"""


def write_config(tmpdir, text=CONFIG_TOML):
    path = Path(tmpdir) / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


class LoadServerConfigTest(unittest.TestCase):
    def test_reads_paths_and_vless_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = gen.load_server_config(write_config(tmp))
        self.assertEqual(server.xhttp_path, "/OTHER/xhttp")
        self.assertEqual(server.ws_path, "/SECRET/vless")
        self.assertEqual([u.name for u in server.users], ["alice", "bob"])
        self.assertEqual(
            server.users[0].vless_id, "11111111-1111-4111-8111-111111111111"
        )

    def test_skips_user_without_vless_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = gen.load_server_config(write_config(tmp))
        self.assertNotIn("legacy-ss-only", [u.name for u in server.users])

    def test_rejects_config_without_vless_paths(self):
        stripped = "[websocket]\nws_path_tcp = \"/SECRET/tcp\"\n"
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                gen.load_server_config(write_config(tmp, stripped))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'generate_xray_json'`

- [ ] **Step 3: Write minimal implementation**

Create `ops/xray-json-sub/generate_xray_json.py`:

```python
#!/usr/bin/env python3
"""Build Xray-JSON subscriptions that balance across the cloud entry nodes.

Reads the authoritative outline-ss-rust config.toml on an entry node and emits
one <user>.json per VLESS-capable user, next to the .conf access keys.
"""

from __future__ import annotations

import sys
import tomllib
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: PASS — `Ran 3 tests`, `OK`

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/xray-json-sub/generate_xray_json.py ops/xray-json-sub/test_generate_xray_json.py
git commit -m "ops(xray-json-sub): parse config.toml into VLESS users and paths"
```

---

### Task 2: Build the six proxy outbounds

**Files:**
- Modify: `ops/xray-json-sub/generate_xray_json.py`
- Test: `ops/xray-json-sub/test_generate_xray_json.py`

**Interfaces:**
- Consumes: `User`, `ServerConfig` from Task 1.
- Produces: `DEFAULT_NODES: tuple[str, ...]`, `node_tag(node: str) -> str`, `build_outbounds(vless_id: str, xhttp_path: str, ws_path: str, nodes: Sequence[str]) -> list[dict]`. The returned list is six proxy outbounds followed by `direct` then `block`.

- [ ] **Step 1: Write the failing test**

Append to `ops/xray-json-sub/test_generate_xray_json.py`, before the
`if __name__` block:

```python
NODES = ("cloud1.beerloga.su", "cloud2.beerloga.su")
UUID = "11111111-1111-4111-8111-111111111111"


def build():
    return gen.build_outbounds(UUID, "/OTHER/xhttp", "/SECRET/vless", NODES)


class BuildOutboundsTest(unittest.TestCase):
    def test_tag_order_puts_proxies_first_and_direct_last(self):
        tags = [o["tag"] for o in build()]
        self.assertEqual(
            tags,
            [
                "cloud1-xhttp-h3",
                "cloud2-xhttp-h3",
                "cloud1-xhttp-h2",
                "cloud2-xhttp-h2",
                "cloud1-ws",
                "cloud2-ws",
                "direct",
                "block",
            ],
        )

    def test_first_outbound_is_never_direct(self):
        # leastPing routes to outbounds[0] until the first probe lands.
        self.assertNotEqual(build()[0]["tag"], "direct")

    def test_h3_legs_carry_exactly_h3(self):
        for outbound in build():
            if outbound["tag"].endswith("-xhttp-h3"):
                self.assertEqual(
                    outbound["streamSettings"]["tlsSettings"]["alpn"], ["h3"]
                )

    def test_h2_legs_carry_exactly_h2(self):
        for outbound in build():
            if outbound["tag"].endswith("-xhttp-h2"):
                self.assertEqual(
                    outbound["streamSettings"]["tlsSettings"]["alpn"], ["h2"]
                )

    def test_ws_legs_carry_http11_because_xray_cannot_do_rfc8441(self):
        for outbound in build():
            if outbound["tag"].endswith("-ws"):
                self.assertEqual(
                    outbound["streamSettings"]["tlsSettings"]["alpn"], ["http/1.1"]
                )

    def test_xhttp_legs_use_stream_one_and_the_xhttp_path(self):
        legs = [o for o in build() if "-xhttp-" in o["tag"]]
        self.assertEqual(len(legs), 4)
        for outbound in legs:
            stream = outbound["streamSettings"]
            self.assertEqual(stream["network"], "xhttp")
            self.assertEqual(stream["xhttpSettings"]["mode"], "stream-one")
            self.assertEqual(stream["xhttpSettings"]["path"], "/OTHER/xhttp")

    def test_ws_legs_use_the_ws_path(self):
        legs = [o for o in build() if o["tag"].endswith("-ws")]
        self.assertEqual(len(legs), 2)
        for outbound in legs:
            self.assertEqual(outbound["streamSettings"]["network"], "ws")
            self.assertEqual(outbound["streamSettings"]["wsSettings"]["path"], "/SECRET/vless")

    def test_each_leg_addresses_its_own_node_by_name(self):
        # Not cloud.beerloga.su: round-robin DNS would make the probe measure
        # a different node than the tag claims.
        for outbound in build()[:6]:
            expected = "cloud1.beerloga.su" if outbound["tag"].startswith("cloud1") else "cloud2.beerloga.su"
            vnext = outbound["settings"]["vnext"][0]
            self.assertEqual(vnext["address"], expected)
            self.assertEqual(vnext["port"], 443)
            self.assertEqual(vnext["users"][0]["id"], UUID)
            self.assertEqual(vnext["users"][0]["encryption"], "none")
            self.assertEqual(outbound["streamSettings"]["tlsSettings"]["serverName"], expected)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: FAIL — `AttributeError: module 'generate_xray_json' has no attribute 'build_outbounds'`

- [ ] **Step 3: Write minimal implementation**

Add to `ops/xray-json-sub/generate_xray_json.py` — extend the imports at the top
to `from collections.abc import Sequence`, then append below `load_server_config`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: PASS — `Ran 11 tests`, `OK`

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/xray-json-sub/generate_xray_json.py ops/xray-json-sub/test_generate_xray_json.py
git commit -m "ops(xray-json-sub): build six VLESS outbounds across node and transport axes"
```

---

### Task 3: Assemble the full document — inbounds, routing, balancer, observatory

**Files:**
- Modify: `ops/xray-json-sub/generate_xray_json.py`
- Test: `ops/xray-json-sub/test_generate_xray_json.py`

**Interfaces:**
- Consumes: `User`, `ServerConfig`, `build_outbounds`, `node_tag` from Tasks 1–2.
- Produces: `PRIVATE_CIDRS: list[str]`, `PING_DESTINATION: str`, `BALANCER_TAG: str`, `build_config(user: User, server: ServerConfig, nodes: Sequence[str]) -> dict` — one complete Xray config (not yet wrapped in the array).

- [ ] **Step 1: Write the failing test**

Append to `ops/xray-json-sub/test_generate_xray_json.py`, before the
`if __name__` block:

```python
class BuildConfigTest(unittest.TestCase):
    def setUp(self):
        self.server = gen.ServerConfig(
            xhttp_path="/OTHER/xhttp",
            ws_path="/SECRET/vless",
            users=(gen.User(name="alice", vless_id=UUID),),
        )
        self.doc = gen.build_config(self.server.users[0], self.server, NODES)

    def test_remarks_name_the_user(self):
        self.assertIn("alice", self.doc["remarks"])

    def test_socks_inbound_comes_first_on_10808(self):
        # iOS/macOS builds of Happ expect socks before any other inbound.
        inbounds = self.doc["inbounds"]
        self.assertEqual(inbounds[0]["tag"], "socks-in")
        self.assertEqual(inbounds[0]["protocol"], "socks")
        self.assertEqual(inbounds[0]["port"], 10808)
        self.assertTrue(inbounds[0]["settings"]["udp"])
        self.assertEqual(inbounds[1]["tag"], "http-in")
        self.assertEqual(inbounds[1]["port"], 10809)

    def test_socks_inbound_sniffs_so_domains_survive_the_tun(self):
        sniffing = self.doc["inbounds"][0]["sniffing"]
        self.assertTrue(sniffing["enabled"])
        self.assertEqual(sniffing["destOverride"], ["http", "tls", "quic"])
        self.assertFalse(sniffing["routeOnly"])

    def test_routing_sends_private_direct_then_everything_to_the_balancer(self):
        rules = self.doc["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "direct")
        self.assertIn("192.168.0.0/16", rules[0]["ip"])
        self.assertIn("fc00::/7", rules[0]["ip"])
        self.assertEqual(rules[1]["network"], "tcp,udp")
        self.assertEqual(rules[1]["balancerTag"], gen.BALANCER_TAG)

    def test_domain_strategy_is_asis_so_resolution_happens_server_side(self):
        self.assertEqual(self.doc["routing"]["domainStrategy"], "AsIs")

    def test_no_geoip_or_geosite_tokens_anywhere(self):
        # Happ may hand the core trimmed geo databases in JSON mode.
        blob = json.dumps(self.doc)
        self.assertNotIn("geoip:", blob)
        self.assertNotIn("geosite:", blob)

    def test_balancer_selector_matches_every_proxy_leg(self):
        balancer = self.doc["routing"]["balancers"][0]
        self.assertEqual(balancer["tag"], gen.BALANCER_TAG)
        self.assertEqual(balancer["strategy"], {"type": "leastPing"})
        proxy_tags = [o["tag"] for o in self.doc["outbounds"]][:6]
        for tag in proxy_tags:
            self.assertTrue(
                any(tag.startswith(prefix) for prefix in balancer["selector"]),
                f"{tag} not covered by selector {balancer['selector']}",
            )

    def test_observatory_probes_the_same_legs(self):
        observatory = self.doc["burstObservatory"]
        self.assertEqual(
            observatory["subjectSelector"], self.doc["routing"]["balancers"][0]["selector"]
        )
        ping = observatory["pingConfig"]
        self.assertEqual(ping["destination"], gen.PING_DESTINATION)
        self.assertEqual(ping["interval"], "30s")
        self.assertEqual(ping["timeout"], "5s")
        self.assertEqual(ping["sampling"], 3)

    def test_no_dns_block(self):
        # AsIs means nothing to resolve locally; Happ owns the tunnel DNS.
        self.assertNotIn("dns", self.doc)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: FAIL — `AttributeError: module 'generate_xray_json' has no attribute 'build_config'`

- [ ] **Step 3: Write minimal implementation**

Append to `ops/xray-json-sub/generate_xray_json.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: PASS — `Ran 20 tests`, `OK`

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/xray-json-sub/generate_xray_json.py ops/xray-json-sub/test_generate_xray_json.py
git commit -m "ops(xray-json-sub): assemble inbounds, routing, balancer and observatory"
```

---

### Task 4: CLI and atomic per-user output

**Files:**
- Modify: `ops/xray-json-sub/generate_xray_json.py`
- Test: `ops/xray-json-sub/test_generate_xray_json.py`

**Interfaces:**
- Consumes: everything from Tasks 1–3.
- Produces: `DEFAULT_CONFIG: str`, `DEFAULT_OUT_DIR: str`, `write_subscription(out_dir: Path, user: User, document: dict) -> Path`, `main(argv: Sequence[str] | None = None) -> int`. CLI flags: `--config`, `--out-dir`, `--node` (repeatable).

- [ ] **Step 1: Write the failing test**

Append to `ops/xray-json-sub/test_generate_xray_json.py`, before the
`if __name__` block:

```python
class WriteAndMainTest(unittest.TestCase):
    def test_document_on_disk_is_a_single_element_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "keys"
            user = gen.User(name="alice", vless_id=UUID)
            gen.write_subscription(out, user, {"remarks": "alice cloud-balancer"})
            payload = json.loads((out / "alice.json").read_text(encoding="utf-8"))
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["remarks"], "alice cloud-balancer")

    def test_written_file_is_world_readable_and_leaves_no_temp_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "keys"
            gen.write_subscription(out, gen.User(name="alice", vless_id=UUID), {})
            target = out / "alice.json"
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o644)
            self.assertEqual([p.name for p in out.iterdir()], ["alice.json"])

    def test_main_writes_one_file_per_vless_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = write_config(tmp)
            out = Path(tmp) / "keys"
            rc = gen.main(["--config", str(config), "--out-dir", str(out)])
            self.assertEqual(rc, 0)
            self.assertEqual(
                sorted(p.name for p in out.iterdir()), ["alice.json", "bob.json"]
            )
            payload = json.loads((out / "bob.json").read_text(encoding="utf-8"))
        tags = [o["tag"] for o in payload[0]["outbounds"]]
        self.assertEqual(tags[0], "cloud1-xhttp-h3")
        self.assertEqual(tags[-2:], ["direct", "block"])

    def test_main_honours_custom_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = write_config(tmp)
            out = Path(tmp) / "keys"
            gen.main(
                [
                    "--config",
                    str(config),
                    "--out-dir",
                    str(out),
                    "--node",
                    "edge9.example.com",
                ]
            )
            payload = json.loads((out / "alice.json").read_text(encoding="utf-8"))
        tags = [o["tag"] for o in payload[0]["outbounds"]]
        self.assertEqual(
            tags, ["edge9-xhttp-h3", "edge9-xhttp-h2", "edge9-ws", "direct", "block"]
        )

    def test_main_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = write_config(tmp)
            out = Path(tmp) / "keys"
            gen.main(["--config", str(config), "--out-dir", str(out)])
            first = (out / "alice.json").read_text(encoding="utf-8")
            gen.main(["--config", str(config), "--out-dir", str(out)])
            second = (out / "alice.json").read_text(encoding="utf-8")
        self.assertEqual(first, second)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: FAIL — `AttributeError: module 'generate_xray_json' has no attribute 'write_subscription'`

- [ ] **Step 3: Write minimal implementation**

Extend the imports at the top of `ops/xray-json-sub/generate_xray_json.py` with
`import argparse`, `import json` and `import os`, then append:

```python
DEFAULT_CONFIG = "/opt/outline/outline-ss-rust/config.toml"
DEFAULT_OUT_DIR = "/var/www/html/<keys-dir>"


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
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="outline-ss-rust config.toml")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help="where <user>.json is written")
    parser.add_argument(
        "--node",
        action="append",
        dest="nodes",
        help="entry node hostname; repeat for each. Default: %s" % ", ".join(DEFAULT_NODES),
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`
Expected: PASS — `Ran 25 tests`, `OK`

- [ ] **Step 5: Make the script executable and smoke-test the CLI**

```bash
chmod +x ops/xray-json-sub/generate_xray_json.py
```

Run against a throwaway fixture:

```bash
python3 - <<'PY'
import pathlib, tempfile, subprocess, json, sys
tmp = pathlib.Path(tempfile.mkdtemp())
(tmp / "config.toml").write_text(
    '[websocket]\nws_path_vless = "/S/vless"\nxhttp_path_vless = "/O/xhttp"\n'
    '[[users]]\nid = "smoke"\nvless_id = "11111111-1111-4111-8111-111111111111"\n'
)
subprocess.run([sys.executable, "ops/xray-json-sub/generate_xray_json.py",
                "--config", str(tmp / "config.toml"), "--out-dir", str(tmp / "out")], check=True)
doc = json.loads((tmp / "out" / "smoke.json").read_text())
print("outbound tags:", [o["tag"] for o in doc[0]["outbounds"]])
PY
```

Expected: `wrote …/smoke.json`, then
`outbound tags: ['cloud1-xhttp-h3', 'cloud2-xhttp-h3', 'cloud1-xhttp-h2', 'cloud2-xhttp-h2', 'cloud1-ws', 'cloud2-ws', 'direct', 'block']`

- [ ] **Step 6: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/xray-json-sub/generate_xray_json.py ops/xray-json-sub/test_generate_xray_json.py
git commit -m "ops(xray-json-sub): add CLI and atomic per-user output"
```

---

### Task 5: Verify the generated config against a real Xray core

**Files:**
- No repository changes unless a defect is found.

**Interfaces:**
- Consumes: the CLI from Task 4.
- Produces: evidence that the document is accepted by xray-core and that the balancer fails over. No new symbols.

This is the task that catches schema mistakes the unit tests cannot: a wrong
field name inside `xhttpSettings` still serialises to valid JSON.

- [ ] **Step 1: Get an Xray core on the Mac**

```bash
brew install xray || echo "no formula — download from https://github.com/XTLS/Xray-core/releases"
```

Verify: `xray version` prints a version. If neither works, say so and stop —
do not claim the config was validated when it was not.

- [ ] **Step 2: Generate a real config from a real user**

Pull the live config to a scratch file (read-only; do not print it):

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n cat /opt/outline/outline-ss-rust/config.toml' \
  > /tmp/cloud-config.toml
python3 ops/xray-json-sub/generate_xray_json.py \
  --config /tmp/cloud-config.toml --out-dir /tmp/xray-sub
```

Expected: one `wrote …` line per VLESS user.

- [ ] **Step 3: Start the core against one user's document**

Xray wants a bare config object, while the subscription is an array — unwrap it
for the local run:

```bash
python3 -c "import json,sys;json.dump(json.load(open(sys.argv[1]))[0],open(sys.argv[2],'w'),indent=2)" \
  /tmp/xray-sub/beerloga.json /tmp/xray-run.json
xray run -c /tmp/xray-run.json
```

Expected: the core starts and stays up. Any `infra/conf: … unknown field` or
`failed to parse` line is a real defect — fix the generator and re-run Task 4's
tests before continuing.

- [ ] **Step 4: Prove traffic leaves through an exit node**

In a second terminal:

```bash
curl --max-time 20 --socks5-hostname 127.0.0.1:10808 https://ifconfig.me
```

Expected: an exit-node address, not the home address. Compare against
`curl --max-time 20 https://ifconfig.me` run without the proxy.

- [ ] **Step 5: Prove failover**

Blackhole one node for the local core only, then repeat the curl:

```bash
sudo route -n add -host 176.123.167.42 127.0.0.1   # cloud1 unreachable
curl --max-time 30 --socks5-hostname 127.0.0.1:10808 https://ifconfig.me
sudo route -n delete -host 176.123.167.42          # ALWAYS undo
```

Expected: the request still succeeds — within one observatory interval the
balancer moves to the cloud2 legs. Restore the route immediately afterwards and
confirm with `route -n get 176.123.167.42` that it no longer points at
`127.0.0.1`.

- [ ] **Step 6: Clean up the scratch copies**

```bash
rm -rf /tmp/cloud-config.toml /tmp/xray-sub /tmp/xray-run.json
```

These hold live `vless_id` and passwords; they must not linger.

---

### Task 6: README

**Files:**
- Create: `ops/xray-json-sub/README.md`

**Interfaces:**
- Consumes: the CLI and invariants from Tasks 1–4.
- Produces: no code.

- [ ] **Step 1: Write the README**

In Russian, matching `ops/watchdog/README.md`. It must cover:

- what the script produces (`<user>.json`, one full Xray config in a
  single-element array) and why Happ needs the JSON form at all — no native
  balancing, `fallback-url` is about the subscription URL and not traffic;
- the six-leg table (tag / node / transport / ALPN) and the two axes of failure;
- **the outbound-order invariant**, stated as a warning: proxies first,
  `direct`/`block` last, because a `leastPing` balancer routes to `outbounds[0]`
  until the first probe lands;
- why ALPN values are single-valued, and why the WS legs stay on `http/1.1`
  (xray has no RFC 8441, unlike our server);
- how to run it: `sudo /opt/outline/outline-ss-rust/generate_xray_json.py`, plus
  the `--config` / `--out-dir` / `--node` flags;
- the client URL shape
  `https://cloud.beerloga.su/<keys-dir>/<user>.json` and the note that the path
  segment is the same secret directory as the `.conf` artifacts;
- deployment: `rsync` to both nodes, the `save-keys.sh` hook, one node at a time;
- how to run the tests: `python3 ops/xray-json-sub/test_generate_xray_json.py -v`;
- the known blind spot: observatory probes cannot see a node that answers while
  its traffic leaks outside the tunnel — the 2026-08-11 `ip rule` failure would
  have probed green.

- [ ] **Step 2: Verify the README has no stale paths**

```bash
grep -n "generate_xray_json\|save-keys\|<keys-prefix>" ops/xray-json-sub/README.md
```

Expected: every path matches what the script actually uses.

- [ ] **Step 3: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/xray-json-sub/README.md
git commit -m "ops(xray-json-sub): document the generator and its invariants"
```

---

### Task 7: Roll out to cloud2, then cloud1

**Files:**
- Modify on the nodes: `/opt/outline/outline-ss-rust/save-keys.sh`
- No repository changes.

**Interfaces:**
- Consumes: the verified generator from Tasks 4–5.
- Produces: `<user>.json` served from both entry nodes.

cloud2 goes first: most clients land on cloud1 through round-robin DNS, so a
mistake on cloud2 touches fewer people. Nothing here restarts a service.

- [ ] **Step 1: Copy the generator to cloud2**

```bash
rsync -a ops/xray-json-sub/generate_xray_json.py \
  sysadm@cloud2.beerloga.su:/tmp/generate_xray_json.py
ssh sysadm@cloud2.beerloga.su \
  'sudo -n install -o root -g root -m 0755 /tmp/generate_xray_json.py \
     /opt/outline/outline-ss-rust/generate_xray_json.py && rm /tmp/generate_xray_json.py'
```

- [ ] **Step 2: Dry-run into a scratch directory first**

```bash
ssh sysadm@cloud2.beerloga.su \
  'sudo -n /opt/outline/outline-ss-rust/generate_xray_json.py --out-dir /tmp/xray-sub-check | tail -2'
```

Expected: `N subscription(s) across 2 node(s)`, with N matching the user count
(12 today). Then confirm the shape without printing credentials:

```bash
ssh sysadm@cloud2.beerloga.su \
  'sudo -n jq -r ".[0].outbounds[].tag" /tmp/xray-sub-check/beerloga.json'
```

Expected: the eight tags in order, `direct` and `block` last.

- [ ] **Step 3: Write for real and clean up the scratch copy**

```bash
ssh sysadm@cloud2.beerloga.su \
  'sudo -n /opt/outline/outline-ss-rust/generate_xray_json.py | tail -1 && sudo -n rm -rf /tmp/xray-sub-check'
```

- [ ] **Step 4: Confirm delivery over HTTPS from cloud2 specifically**

```bash
curl -sS --resolve cloud.beerloga.su:443:87.242.85.181 \
  -o /dev/null -w '%{http_code} %{content_type}\n' \
  https://cloud.beerloga.su/<keys-prefix>/beerloga.json
```

Expected: `200 application/json`

- [ ] **Step 5: Import into Happ and confirm it connects**

Add the URL above as a subscription in Happ. Expected: a profile named
`beerloga cloud-balancer` appears and connects. If Happ rejects the file, stop
and report — do not proceed to cloud1.

- [ ] **Step 6: Hook the generator into `save-keys.sh` on cloud2**

Append one line, keeping the existing `outline-ss-rust --write-access-keys-dir`
invocation as the first match for `collect-from-reference.sh`, which greps that
flag out of this file:

```bash
ssh sysadm@cloud2.beerloga.su \
  'sudo -n tee -a /opt/outline/outline-ss-rust/save-keys.sh >/dev/null <<EOF

# Xray-JSON subscriptions with the cloud1+cloud2 balancer (ops/xray-json-sub).
/opt/outline/outline-ss-rust/generate_xray_json.py
EOF'
ssh sysadm@cloud2.beerloga.su 'sudo -n sh -n /opt/outline/outline-ss-rust/save-keys.sh && echo "syntax ok"'
```

Expected: `syntax ok`

- [ ] **Step 7: Verify `collect-from-reference.sh` still finds the keys dir**

That script does `sed -n 's#.*--write-access-keys-dir *##p' … | head -1`, so the
appended line must not shadow it:

```bash
ssh sysadm@cloud2.beerloga.su \
  "sed -n 's#.*--write-access-keys-dir *##p' /opt/outline/outline-ss-rust/save-keys.sh | tr -d ' \\\\' | head -1"
```

Expected: `/var/www/html/<keys-dir>/`

- [ ] **Step 8: Repeat Steps 1–7 for cloud1**

Same commands with `cloud1.beerloga.su`, and `--resolve
cloud.beerloga.su:443:176.123.167.42` in Step 4. Only start once cloud2 is fully
green.

- [ ] **Step 9: Confirm both nodes serve an identical document**

```bash
for ip in 176.123.167.42 87.242.85.181; do
  curl -sS --resolve cloud.beerloga.su:443:$ip \
    https://cloud.beerloga.su/<keys-prefix>/beerloga.json | shasum -a 256
done
```

Expected: two identical hashes. A mismatch means the nodes' paths or credentials
have diverged — investigate before telling anyone the subscription is live.

---

## Notes for the implementer

- **Do not restart `outline-ss-rust` or nginx.** This change only writes files
  that nginx already serves from disk.
- **Do not echo `vless_id`, `password`, or the control token** into the terminal,
  a log, or a commit. `jq -r '.[0].outbounds[].tag'` is safe; `cat` of a
  generated `.json` is not.
- **If a step fails, stop and report** rather than working around it. A
  half-deployed subscription is worse than none: clients would import a config
  pointing at a node that has not been verified.
