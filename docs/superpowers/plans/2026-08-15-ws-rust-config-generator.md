# План: генератор клиентского конфига ws-rust для Android

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** На узле рядом с Xray-подпиской `<user>.json` появляется `<user>.toml` — готовый конфиг `outline-ws-rust` для Android, с цепочкой fallback-носителей на узел, failover между узлами и миграцией живых флоу.

**Architecture:** Новый модуль `ops/access-keys/ws_toml.py` — чистый рендер без I/O, как `xray_json.py`. Данные берёт из уже существующего `config_model.load()` (расширяется тремя серверными секциями) и строит wire'ы существующими функциями `uri.py`. Запись файла, отчёт и предупреждения — в `generate_keys.py`. Формат закрепляется фикстурой, которую грузит штатный загрузчик ws-rust в Rust-тесте.

**Tech Stack:** Python 3.11+ stdlib-only (`tomllib`, `unittest`, `dataclasses`); Rust — тест в `bins/outline-ws-rust/src/config/tests/mod.rs`.

Спека: [`docs/superpowers/specs/2026-08-15-ws-rust-config-generator-design.md`](../specs/2026-08-15-ws-rust-config-generator-design.md).

## Global Constraints

- Python — **только stdlib**. Никаких зависимостей: `ops/access-keys` разворачивается на узлы простым `rsync` без venv. `tomllib` умеет только читать — TOML пишем сами.
- Тесты не ходят в сеть и не пишут за пределы временного каталога. Запуск: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`.
- `golden/expected/` и `<user>.txt` **не меняются**: это эталон, снятый с удалённого режима бинаря, переснять его больше нечем.
- Артефакты несут креды: права `0640`, атомарная запись через `write_atomic`. Никаких паролей и `vless_id` в отчёте и в логах.
- Комментарии в коде — на английском; спеки, планы и диалог — по-русски.
- Коммиты — на английском, без трейлеров `Co-Authored-By` и без пометок про Claude.
- Порядок цепочки wire'ов фиксирован (спека): `vless-xhttp stream-one` → `vless-ws` → `ss-ws` → `ss-xhttp stream-one` → `vless-xhttp packet-up`.
- Группа: `mode = "active_passive"`, `routing_scope = "global"`, `reselect_interval = "6h"`, `tun_wire_dial = true`, `health_weighted_selection = true`, `warm_standby_tcp = 1`, `warm_standby_udp = 1`. `auto_failback` **не выписывается**.
- `[tun] mtu = 1500` — обязано совпадать с `ServerProfile.TUN_MTU` в `android/app/src/main/java/com/outline/proxy/ServerProfile.kt`.

---

### Task 1: Серверные фичи в `config_model`

**Files:**
- Modify: `ops/access-keys/config_model.py`
- Test: `ops/access-keys/test_config_model.py`

**Interfaces:**
- Consumes: ничего (первая задача).
- Produces: `config_model.Padding(enabled: bool, paths: tuple[str, ...])`, `config_model.SessionResumption(enabled: bool, downlink_buffer_bytes: int)`, поля `ServerConfig.padding: Padding`, `ServerConfig.session_resumption: SessionResumption`, `ServerConfig.cluster_enabled: bool`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в конец `ops/access-keys/test_config_model.py`:

```python
class ServerFeaturesTest(unittest.TestCase):
    def load_body(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(body, encoding="utf-8")
            return cm.load(path)

    BASE = """
[access_keys]
public_host = "keys.example.com"

[[users]]
id = "alice"
password = "pw"
"""

    def test_features_default_to_off(self):
        server = self.load_body(self.BASE)
        self.assertFalse(server.padding.enabled)
        self.assertEqual(server.padding.paths, ())
        self.assertFalse(server.session_resumption.enabled)
        self.assertEqual(server.session_resumption.downlink_buffer_bytes, 0)
        self.assertFalse(server.cluster_enabled)

    def test_reads_padding_paths(self):
        server = self.load_body(
            self.BASE
            + """
[padding]
enabled = true
paths = ["/GLOBAL/ss", "/GLOBAL/ssx"]
"""
        )
        self.assertTrue(server.padding.enabled)
        self.assertEqual(server.padding.paths, ("/GLOBAL/ss", "/GLOBAL/ssx"))

    def test_padding_paths_without_enabled_stay_inactive(self):
        server = self.load_body(
            self.BASE
            + """
[padding]
paths = ["/GLOBAL/ss"]
"""
        )
        self.assertFalse(server.padding.enabled)
        self.assertEqual(server.padding.paths, ("/GLOBAL/ss",))

    def test_reads_session_resumption(self):
        server = self.load_body(
            self.BASE
            + """
[session_resumption]
enabled = true
downlink_buffer_bytes = 65536
"""
        )
        self.assertTrue(server.session_resumption.enabled)
        self.assertEqual(server.session_resumption.downlink_buffer_bytes, 65536)

    def test_cluster_needs_explicit_enabled(self):
        with_peers = self.load_body(
            self.BASE
            + """
[cluster]
shard_id = 1
"""
        )
        self.assertFalse(with_peers.cluster_enabled)

        enabled = self.load_body(
            self.BASE
            + """
[cluster]
enabled = true
shard_id = 1
"""
        )
        self.assertTrue(enabled.cluster_enabled)
```

- [ ] **Step 2: Прогнать тесты и убедиться, что они падают**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_config_model.py" -v`
Expected: FAIL — `AttributeError: 'ServerConfig' object has no attribute 'padding'`.

- [ ] **Step 3: Реализовать**

В `ops/access-keys/config_model.py` добавить два датакласса перед `ServerConfig`:

```python
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
```

Расширить `ServerConfig` (дефолты обязательны — существующие тесты конструируют его позиционно):

```python
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
```

В конце `load()` заменить `return ServerConfig(...)` на:

```python
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
```

- [ ] **Step 4: Прогнать тесты**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`
Expected: OK, число тестов выросло на 5 (было 123).

- [ ] **Step 5: Коммит**

```bash
git add ops/access-keys/config_model.py ops/access-keys/test_config_model.py
git commit -m "feat(access-keys): read padding, session-resumption and cluster flags from the node config"
```

---

### Task 2: Цепочка wire'ов

**Files:**
- Create: `ops/access-keys/ws_toml.py`
- Test: `ops/access-keys/test_ws_toml.py`

**Interfaces:**
- Consumes: `config_model.User`, `uri.vless_xhttp_uri`, `uri.vless_ws_uri`, `uri.ss_ws_uri`, `uri.ss_xhttp_uri`, `uri.alpn_list`.
- Produces: `ws_toml.Wire(link: str, path: str)`, `ws_toml.build_wires(user, node: str, scheme: str, has_h3: bool) -> list[Wire]`, `ws_toml.has_wires(user) -> bool`.

- [ ] **Step 1: Написать падающий тест**

Создать `ops/access-keys/test_ws_toml.py`:

```python
#!/usr/bin/env python3
"""Offline tests for ws_toml.py. Stdlib only; no network, no node access."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ws_toml as gen  # noqa: E402
from config_model import User  # noqa: E402

NODE = "cloud1.beerloga.su"
UUID = "11111111-1111-4111-8111-111111111111"


def make_user(
    name="alice",
    password="pw-alice",
    vless_id=UUID,
    ws_path_vless="/SECRET/vless",
    xhttp_path_vless="/SECRET/xhttp",
    ws_path_ss="/SECRET/ss",
    xhttp_path_ss="/SECRET/ssx",
):
    return User(
        name=name,
        filename=name,
        password=password,
        method="chacha20-ietf-poly1305",
        vless_id=vless_id,
        ws_path_tcp="/SECRET/tcp",
        ws_path_udp="/SECRET/udp",
        ws_path_vless=ws_path_vless,
        ws_path_ss=ws_path_ss,
        xhttp_path_vless=xhttp_path_vless,
        xhttp_path_ss=xhttp_path_ss,
    )


class BuildWiresTest(unittest.TestCase):
    def test_full_chain_order(self):
        wires = gen.build_wires(make_user(), NODE, "wss", has_h3=True)
        self.assertEqual(
            [w.path for w in wires],
            ["/SECRET/xhttp", "/SECRET/vless", "/SECRET/ss", "/SECRET/ssx", "/SECRET/xhttp"],
        )
        self.assertIn("type=xhttp&mode=stream-one", wires[0].link)
        self.assertIn("type=ws", wires[1].link)
        self.assertTrue(wires[2].link.startswith("ss://"))
        self.assertIn("type=xhttp&mode=stream-one", wires[3].link)
        self.assertIn("type=xhttp&mode=packet-up", wires[4].link)

    def test_h3_alpn_leads_every_link(self):
        wires = gen.build_wires(make_user(), NODE, "wss", has_h3=True)
        self.assertIn("alpn=h3", wires[0].link)
        self.assertIn("alpn=h3", wires[2].link)

    def test_without_h3_links_lead_with_h2(self):
        wires = gen.build_wires(make_user(), NODE, "wss", has_h3=False)
        for wire in wires:
            self.assertNotIn("alpn=h3", wire.link)
            self.assertIn("alpn=h2", wire.link)

    def test_ss_only_user_keeps_ss_wires(self):
        user = make_user(vless_id=None)
        wires = gen.build_wires(user, NODE, "wss", has_h3=True)
        self.assertEqual([w.path for w in wires], ["/SECRET/ss", "/SECRET/ssx"])
        self.assertTrue(all(w.link.startswith("ss://") for w in wires))

    def test_vless_only_user_keeps_vless_wires(self):
        user = make_user(password=None)
        wires = gen.build_wires(user, NODE, "wss", has_h3=True)
        self.assertEqual(
            [w.path for w in wires], ["/SECRET/xhttp", "/SECRET/vless", "/SECRET/xhttp"]
        )
        self.assertTrue(all(w.link.startswith("vless://") for w in wires))

    def test_missing_paths_shrink_the_chain(self):
        user = make_user(xhttp_path_vless=None, xhttp_path_ss=None)
        wires = gen.build_wires(user, NODE, "wss", has_h3=True)
        self.assertEqual([w.path for w in wires], ["/SECRET/vless", "/SECRET/ss"])

    def test_links_address_the_requested_node(self):
        wires = gen.build_wires(make_user(), "cloud2.beerloga.su", "wss", has_h3=True)
        for wire in wires:
            self.assertIn("@cloud2.beerloga.su:443?", wire.link)

    def test_has_wires_needs_a_credential_and_a_path(self):
        self.assertTrue(gen.has_wires(make_user()))
        self.assertFalse(
            gen.has_wires(
                make_user(
                    password=None,
                    vless_id=None,
                )
            )
        )
        self.assertFalse(
            gen.has_wires(
                make_user(
                    password=None,
                    ws_path_vless=None,
                    xhttp_path_vless=None,
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Прогнать тест и убедиться, что он падает**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_ws_toml.py" -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ws_toml'`.

- [ ] **Step 3: Реализовать**

Создать `ops/access-keys/ws_toml.py`:

```python
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

from collections.abc import Sequence
from dataclasses import dataclass

import uri
from config_model import User

PORT = 443


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
    that dials nothing.
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
```

Дописать split-SS в цепочку **нельзя**: `ss://` разворачивается только в combined-путь, для `ws_path_tcp` / `ws_path_udp` формы ссылки нет (см. спеку).

- [ ] **Step 4: Прогнать тесты**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`
Expected: OK.

- [ ] **Step 5: Коммит**

```bash
git add ops/access-keys/ws_toml.py ops/access-keys/test_ws_toml.py
git commit -m "feat(access-keys): build the ws-rust carrier chain from share links"
```

---

### Task 3: Рендер полного TOML

**Files:**
- Modify: `ops/access-keys/ws_toml.py`
- Test: `ops/access-keys/test_ws_toml.py`

**Interfaces:**
- Consumes: `ws_toml.build_wires`, `ws_toml.Wire`, `config_model.ServerConfig`.
- Produces: `ws_toml.build_config(user, nodes: Sequence[str], server: ServerConfig) -> str | None` — готовый текст `<user>.toml`, либо `None`, если у юзера нет ни одного wire'а. `ws_toml.pads_every_wire(user, nodes, server) -> bool`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `ops/access-keys/test_ws_toml.py` (после `BuildWiresTest`), плюс добавить импорты `tomllib` и `config_model` в шапку файла:

```python
import tomllib  # add to the imports at the top of the file

from config_model import AccessKeys, Padding, ServerConfig, SessionResumption  # noqa: E402

NODES = ("cloud1.beerloga.su", "cloud2.beerloga.su")

ACCESS_KEYS = AccessKeys(
    public_host="keys.example.com",
    public_scheme="wss",
    url_base="https://keys.example.com/SECRET",
    file_extension=".conf",
    write_dir="/var/www/html/SECRET",
)


def make_server(
    users=(),
    has_h3=True,
    padding=Padding(enabled=False, paths=()),
    resumption=SessionResumption(enabled=False, downlink_buffer_bytes=0),
    cluster_enabled=False,
):
    return ServerConfig(
        access_keys=ACCESS_KEYS,
        users=tuple(users),
        alpn_has_h3=has_h3,
        padding=padding,
        session_resumption=resumption,
        cluster_enabled=cluster_enabled,
    )


class BuildConfigTest(unittest.TestCase):
    def render(self, user=None, **kwargs):
        user = user or make_user()
        return gen.build_config(user, NODES, make_server(users=[user], **kwargs))

    def parsed(self, **kwargs):
        return tomllib.loads(self.render(**kwargs))

    def test_returns_none_without_wires(self):
        user = make_user(password=None, vless_id=None)
        server = make_server(users=[user])
        self.assertIsNone(gen.build_config(user, NODES, server))

    def test_one_uplink_per_node_named_after_it(self):
        doc = self.parsed()
        uplinks = doc["outline"]["uplinks"]
        self.assertEqual([u["name"] for u in uplinks], ["cloud1", "cloud2"])
        self.assertEqual([u["group"] for u in uplinks], ["main", "main"])
        self.assertEqual([u["weight"] for u in uplinks], [1.0, 1.0])

    def test_primary_is_the_first_wire_rest_are_fallbacks(self):
        doc = self.parsed()
        uplink = doc["outline"]["uplinks"][0]
        self.assertIn("type=xhttp&mode=stream-one", uplink["link"])
        self.assertEqual(len(uplink["fallbacks"]), 4)
        self.assertIn("type=ws", uplink["fallbacks"][0]["link"])
        self.assertTrue(uplink["fallbacks"][1]["link"].startswith("ss://"))

    def test_uplinks_shuffle_wires(self):
        doc = self.parsed()
        self.assertTrue(all(u["shuffle_wires"] for u in doc["outline"]["uplinks"]))

    def test_group_is_active_passive_global_without_auto_failback(self):
        group = self.parsed()["uplink_group"][0]
        self.assertEqual(group["name"], "main")
        self.assertEqual(group["mode"], "active_passive")
        self.assertEqual(group["routing_scope"], "global")
        self.assertEqual(group["reselect_interval"], "6h")
        self.assertTrue(group["tun_wire_dial"])
        self.assertTrue(group["health_weighted_selection"])
        self.assertEqual(group["warm_standby_tcp"], 1)
        self.assertEqual(group["warm_standby_udp"], 1)
        self.assertNotIn("auto_failback", group)

    def test_shared_resume_follows_the_server_cluster(self):
        self.assertFalse(self.parsed()["uplink_group"][0]["shared_resume"])
        self.assertTrue(
            self.parsed(cluster_enabled=True)["uplink_group"][0]["shared_resume"]
        )

    def test_android_tun_profile(self):
        doc = self.parsed()
        self.assertEqual(doc["tun"]["path"], "vpn")
        self.assertEqual(doc["tun"]["mtu"], 1500)
        self.assertTrue(doc["tun"]["tcp"]["sniffing"])
        self.assertTrue(doc["tun"]["tcp"]["carrier_migration"])

    def test_no_host_sections_absent_from_the_android_build(self):
        doc = self.parsed()
        for section in ("socks5", "metrics", "control", "dashboard"):
            self.assertNotIn(section, doc)

    def test_padding_on_when_the_server_pads_every_path(self):
        padded = Padding(
            enabled=True,
            paths=("/SECRET/xhttp", "/SECRET/vless", "/SECRET/ss", "/SECRET/ssx"),
        )
        self.assertTrue(self.parsed(padding=padded)["padding"]["enabled"])

    def test_padding_off_on_partial_coverage(self):
        partial = Padding(enabled=True, paths=("/SECRET/ss",))
        self.assertFalse(self.parsed(padding=partial)["padding"]["enabled"])

    def test_padding_off_when_the_server_does_not_pad(self):
        self.assertFalse(self.parsed()["padding"]["enabled"])

    def test_pads_every_wire_predicate(self):
        user = make_user()
        full = Padding(
            enabled=True,
            paths=("/SECRET/xhttp", "/SECRET/vless", "/SECRET/ss", "/SECRET/ssx"),
        )
        self.assertTrue(
            gen.pads_every_wire(user, NODES, make_server(users=[user], padding=full))
        )
        self.assertFalse(
            gen.pads_every_wire(
                user,
                NODES,
                make_server(users=[user], padding=Padding(enabled=True, paths=("/SECRET/ss",))),
            )
        )

    def test_document_is_valid_toml_and_ends_with_a_newline(self):
        text = self.render()
        self.assertTrue(text.endswith("\n"))
        tomllib.loads(text)  # raises on malformed output

    def test_quotes_in_values_are_escaped(self):
        self.assertEqual(gen.quote('a"b\\c'), '"a\\"b\\\\c"')
```

- [ ] **Step 2: Прогнать тесты и убедиться, что они падают**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_ws_toml.py" -v`
Expected: FAIL — `AttributeError: module 'ws_toml' has no attribute 'build_config'`.

- [ ] **Step 3: Реализовать**

Дописать в `ops/access-keys/ws_toml.py` (после `has_wires`):

```python
GROUP = "main"
TUN_MTU = 1500  # MUST match ServerProfile.TUN_MTU / VpnService.Builder.setMtu
RESELECT_INTERVAL = "6h"


def quote(value: str) -> str:
    """TOML basic string. `tomllib` only reads, so the writer is ours."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def node_name(node: str) -> str:
    """cloud1.beerloga.su -> cloud1. Also the uplink's name."""
    return node.split(".", 1)[0]


def pads_every_wire(user: User, nodes: Sequence[str], server) -> bool:
    """Whether the client may switch carrier padding on.

    The client knob is global — there is no per-wire override — and padding is
    config-synchronised rather than negotiated. Padding a path the server
    serves plain feeds padded frames into its plain decoder and kills the
    session, so partial coverage means the whole switch stays off.
    """
    if not server.padding.enabled:
        return False
    padded = set(server.padding.paths)
    paths = {
        wire.path
        for node in nodes
        for wire in build_wires(user, node, server.access_keys.public_scheme, server.alpn_has_h3)
    }
    return bool(paths) and paths.issubset(padded)


def build_config(user: User, nodes: Sequence[str], server) -> str | None:
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
                "shuffle_wires = true",
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
```

- [ ] **Step 4: Прогнать тесты**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`
Expected: OK.

- [ ] **Step 5: Коммит**

```bash
git add ops/access-keys/ws_toml.py ops/access-keys/test_ws_toml.py
git commit -m "feat(access-keys): render the ws-rust Android config document"
```

---

### Task 4: Предупреждения о выключенных серверных фичах

**Files:**
- Modify: `ops/access-keys/ws_toml.py`
- Test: `ops/access-keys/test_ws_toml.py`

**Interfaces:**
- Consumes: `ws_toml.pads_every_wire`, `ws_toml.build_wires`, `config_model.ServerConfig`.
- Produces: `ws_toml.config_warnings(user, nodes: Sequence[str], server) -> list[str]` — строки для отчёта, без кредов.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `ops/access-keys/test_ws_toml.py`:

```python
class WarningsTest(unittest.TestCase):
    def warn(self, **kwargs):
        user = make_user()
        return gen.config_warnings(user, NODES, make_server(users=[user], **kwargs))

    def test_reports_disabled_resumption(self):
        text = " ".join(self.warn())
        self.assertIn("session_resumption", text)

    def test_reports_missing_downlink_replay(self):
        text = " ".join(
            self.warn(resumption=SessionResumption(enabled=True, downlink_buffer_bytes=0))
        )
        self.assertIn("downlink_buffer_bytes", text)

    def test_silent_when_resumption_is_complete(self):
        text = " ".join(
            self.warn(
                resumption=SessionResumption(enabled=True, downlink_buffer_bytes=65536),
                cluster_enabled=True,
                padding=Padding(
                    enabled=True,
                    paths=("/SECRET/xhttp", "/SECRET/vless", "/SECRET/ss", "/SECRET/ssx"),
                ),
            )
        )
        self.assertEqual(text, "")

    def test_reports_uplink_switch_resets_without_a_cluster(self):
        text = " ".join(self.warn())
        self.assertIn("cluster", text)

    def test_reports_partial_padding_coverage_with_the_paths(self):
        text = " ".join(self.warn(padding=Padding(enabled=True, paths=("/SECRET/ss",))))
        self.assertIn("padding", text)
        self.assertIn("/SECRET/vless", text)

    def test_silent_about_padding_the_server_does_not_use(self):
        text = " ".join(self.warn())
        self.assertNotIn("padding", text)

    def test_warnings_never_carry_credentials(self):
        for line in self.warn(padding=Padding(enabled=True, paths=("/SECRET/ss",))):
            self.assertNotIn("pw-alice", line)
            self.assertNotIn(UUID, line)
```

- [ ] **Step 2: Прогнать тесты и убедиться, что они падают**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_ws_toml.py" -v`
Expected: FAIL — `AttributeError: module 'ws_toml' has no attribute 'config_warnings'`.

- [ ] **Step 3: Реализовать**

Дописать в `ops/access-keys/ws_toml.py`:

```python
def config_warnings(user: User, nodes: Sequence[str], server) -> list[str]:
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
        padded = set(server.padding.paths)
        missing = sorted(
            {
                wire.path
                for node in nodes
                for wire in build_wires(
                    user, node, server.access_keys.public_scheme, server.alpn_has_h3
                )
            }
            - padded
        )
        out.append(
            "padding stays off: the node pads only some of this user's carrier paths; "
            "unpadded " + ", ".join(missing)
        )

    return out
```

- [ ] **Step 4: Прогнать тесты**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`
Expected: OK.

- [ ] **Step 5: Коммит**

```bash
git add ops/access-keys/ws_toml.py ops/access-keys/test_ws_toml.py
git commit -m "feat(access-keys): report which server switches the ws-rust config is missing"
```

---

### Task 5: Запись `<user>.toml` и отчёт

**Files:**
- Modify: `ops/access-keys/artifacts.py`
- Modify: `ops/access-keys/generate_keys.py:37-43,140-162`
- Test: `ops/access-keys/test_generate_keys.py`, `ops/access-keys/test_artifacts.py`

**Interfaces:**
- Consumes: `ws_toml.build_config`, `ws_toml.config_warnings`, `ws_toml.has_wires`.
- Produces: `artifacts.ws_url(user, ak) -> str | None`; в отчёте строки `written_toml:`, `ws_url:`, `warning:`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `ops/access-keys/test_artifacts.py`:

```python
class WsUrlTest(unittest.TestCase):
    def test_ws_url_is_the_toml_next_to_the_others(self):
        server = cm.load(GOLDEN)
        user = next(u for u in server.users if u.name == "both")
        self.assertEqual(
            artifacts.ws_url(user, server.access_keys),
            "https://keys.example.com/SECRET/both.toml",
        )

    def test_no_ws_url_without_wires(self):
        server = cm.load(GOLDEN)
        # Every enabled user in the golden config inherits the global SS/VLESS
        # paths, so an undialable user has to be built by hand.
        bare = replace(
            next(u for u in server.users if u.name == "ss-only"),
            password=None,
            vless_id=None,
        )
        self.assertIsNone(artifacts.ws_url(bare, server.access_keys))
```

В шапке `test_artifacts.py` должны быть `import config_model as cm`, `from dataclasses import replace` и `GOLDEN = HERE / "golden" / "config.toml"` — добавить, если их там ещё нет (образец — шапка `test_config_model.py`).

Дописать в `ops/access-keys/test_generate_keys.py`:

```python
class WsTomlArtifactTest(unittest.TestCase):
    def test_writes_toml_and_reports_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            code = generate_keys.main(
                ["--config", str(GOLDEN), "--out-dir", str(out)]
            )
            self.assertEqual(code, 0)
            written = out / "both.toml"
            self.assertTrue(written.exists())
            self.assertIn("[[outline.uplinks]]", written.read_text(encoding="utf-8"))

    def test_toml_is_not_world_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            generate_keys.main(["--config", str(GOLDEN), "--out-dir", str(out)])
            mode = (out / "both.toml").stat().st_mode & 0o777
            self.assertEqual(mode, 0o640)

    def test_report_carries_the_toml_path_and_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                generate_keys.main(["--config", str(GOLDEN), "--out-dir", str(out)])
            report = buffer.getvalue()
            self.assertIn("written_toml:", report)
            self.assertIn("ws_url: https://keys.example.com/SECRET/both.toml", report)

    def test_report_warns_about_missing_server_switches(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                generate_keys.main(["--config", str(GOLDEN), "--out-dir", str(out)])
            # The golden config enables neither session_resumption nor cluster.
            self.assertIn("warning: carrier migration is inert", buffer.getvalue())

    def test_dry_run_writes_no_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            generate_keys.main(
                ["--config", str(GOLDEN), "--out-dir", str(out), "--dry-run"]
            )
            self.assertFalse((out / "both.toml").exists())
```

Если в `test_generate_keys.py` ещё нет `io` / `contextlib` — добавить их в импорты.

- [ ] **Step 2: Прогнать тесты и убедиться, что они падают**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_generate_keys.py" -v`
Expected: FAIL — `FileNotFoundError` / `AssertionError: False is not true` на `both.toml`.

- [ ] **Step 3: Реализовать**

В `ops/access-keys/artifacts.py` добавить импорт `import ws_toml` рядом с `import uri` и функцию после `happ_url`:

```python
def ws_url(user: User, ak: AccessKeys) -> str | None:
    """The link handed to the Android client: the ws-rust config.

    Always `.toml` — `file_extension` applies to the Outline artifact only.
    """
    if not ak.url_base or not ws_toml.has_wires(user):
        return None
    return uri.join_url(ak.url_base, f"{user.filename}.toml")
```

В `ops/access-keys/generate_keys.py`:

1. добавить `import ws_toml  # noqa: E402` рядом с `import xray_json`;
2. расширить `_REPORT_FIELDS`:

```python
_REPORT_FIELDS = (
    ("conf", "written_conf"),
    ("json", "written_json"),
    ("toml", "written_toml"),
    ("txt", "written_txt"),
    ("outline_url", "outline_url"),
    ("happ_url", "happ_url"),
    ("ws_url", "ws_url"),
)
```

3. печатать предупреждения в `render_report` — заменить тело цикла:

```python
def render_report(written: Sequence[dict]) -> str:
    blocks = []
    for record in written:
        lines = [f"user: {record['user']}"]
        lines.extend(
            f"{label}: {record[key]}" for key, label in _REPORT_FIELDS if record.get(key)
        )
        # Never a credential: these name server-side switches and carrier paths.
        lines.extend(f"warning: {text}" for text in record.get("warnings", ()))
        blocks.append("".join(f"{line}\n" for line in lines))
    return "\n".join(blocks)
```

4. в `main()` — после блока, пишущего `.json`, вставить:

```python
        document = ws_toml.build_config(user, nodes, server)
        if document is not None:
            target = out_dir / f"{user.filename}.toml"
            if not args.dry_run:
                write_atomic(target, document)
            record["toml"] = str(target)
            record["warnings"] = ws_toml.config_warnings(user, nodes, server)
```

5. рядом с `record["happ_url"] = …` добавить `record["ws_url"] = artifacts.ws_url(user, ak)`.

- [ ] **Step 4: Прогнать все тесты, включая golden**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`
Expected: OK. Ключевое: `test_artifacts.py` (golden-корпус, 32 артефакта) остаётся зелёным — `<user>.txt` и `<user>.conf` не изменились.

- [ ] **Step 5: Коммит**

```bash
git add ops/access-keys/artifacts.py ops/access-keys/generate_keys.py \
  ops/access-keys/test_artifacts.py ops/access-keys/test_generate_keys.py
git commit -m "feat(access-keys): write the ws-rust config artifact and report it"
```

---

### Task 6: Фикстура + загрузка её штатным загрузчиком ws-rust

**Files:**
- Create: `ops/access-keys/golden/expected-ws/both.toml`
- Create: `ops/access-keys/golden/expected-ws/ss-only.toml`
- Modify: `ops/access-keys/test_ws_toml.py`
- Modify: `bins/outline-ws-rust/src/config/tests/mod.rs`

**Interfaces:**
- Consumes: `ws_toml.build_config`, `config_model.load`.
- Produces: фикстуры, на которые ссылается Rust-тест `ws_toml_fixture_loads`.

- [ ] **Step 1: Написать падающий Python-тест сверки с фикстурой**

Дописать в `ops/access-keys/test_ws_toml.py`:

```python
GOLDEN_CONFIG = HERE / "golden" / "config.toml"
FIXTURES = HERE / "golden" / "expected-ws"


class FixtureTest(unittest.TestCase):
    """The fixture pins the accepted format; the Rust side proves it loads."""

    def test_matches_the_checked_in_fixtures(self):
        import config_model

        server = config_model.load(GOLDEN_CONFIG)
        for name in ("both", "ss-only"):
            user = next(u for u in server.users if u.name == name)
            expected = (FIXTURES / f"{name}.toml").read_text(encoding="utf-8")
            self.assertEqual(gen.build_config(user, NODES, server), expected, name)
```

- [ ] **Step 2: Прогнать тест и убедиться, что он падает**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_ws_toml.py" -v`
Expected: FAIL — `FileNotFoundError: .../golden/expected-ws/both.toml`.

- [ ] **Step 3: Сгенерировать фикстуры**

```bash
mkdir -p ops/access-keys/golden/expected-ws
python3 - <<'PY'
import sys
from pathlib import Path

here = Path("ops/access-keys")
sys.path.insert(0, str(here.resolve()))
import config_model, ws_toml

server = config_model.load(here / "golden" / "config.toml")
nodes = ("cloud1.beerloga.su", "cloud2.beerloga.su")
for name in ("both", "ss-only"):
    user = next(u for u in server.users if u.name == name)
    out = here / "golden" / "expected-ws" / f"{name}.toml"
    out.write_text(ws_toml.build_config(user, nodes, server), encoding="utf-8")
    print("wrote", out)
PY
```

Прочитать оба файла глазами: в них не должно быть ничего, кроме секций `[tun]`, `[tun.tcp]`, `[padding]`, `[[uplink_group]]` и аплинков; `both.toml` должен нести пять wire'ов на узел, `ss-only.toml` — два.

- [ ] **Step 4: Прогнать Python-тесты**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`
Expected: OK.

- [ ] **Step 5: Написать падающий Rust-тест**

Дописать в конец `bins/outline-ws-rust/src/config/tests/mod.rs`:

```rust
/// The generated Android config must load through the real loader, not merely
/// parse as TOML. The schema is `deny_unknown_fields`: one key that drifted
/// from the generator's idea of it aborts the binary at startup — exactly how
/// a stale `[dashboard]` block took nodes down. Failing here keeps that in CI
/// instead of on someone's phone.
#[cfg(feature = "tun")]
#[tokio::test]
async fn generated_android_config_fixture_loads() {
    let path = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ops/access-keys/golden/expected-ws/both.toml"
    ));

    let args = super::Args::parse_from(["test"]);
    let config = load_config(path, &args).await.unwrap();

    let tun = config.tun.as_ref().expect("fixture enables TUN");
    assert_eq!(tun.mtu, 1500);
    assert!(tun.tcp.sniffing);
    assert!(tun.tcp.carrier_migration);

    let group = config
        .groups
        .iter()
        .find(|g| g.name == "main")
        .expect("fixture declares the main group");
    assert_eq!(group.uplinks.len(), 2);
    // Five carriers per node: primary plus four fallbacks.
    assert_eq!(group.uplinks[0].fallbacks.len(), 4);
    assert_eq!(group.load_balancing.mode, LoadBalancingMode::ActivePassive);
    assert_eq!(group.load_balancing.routing_scope, RoutingScope::Global);
    assert!(!group.load_balancing.shared_resume);
    assert_eq!(group.load_balancing.warm_standby_tcp, 1);
}
```

`LoadBalancingMode` и `RoutingScope` уже импортированы в шапке этого файла
(`use outline_uplink::{LoadBalancingConfig, LoadBalancingMode, RoutingScope, UplinkTransport};`).
Имя варианта `RoutingScope::Global` / `LoadBalancingMode::ActivePassive` сверить
по `crates/outline-uplink/src/config.rs` и поправить, если в enum'е они
называются иначе.

- [ ] **Step 6: Прогнать Rust-тест и убедиться, что он падает, а затем зеленеет**

Run: `cargo test -p outline-ws-rust generated_android_config_fixture_loads`
Expected: сначала FAIL, если фикстура ещё не на месте или имена полей не сошлись; после правки ассертов — PASS. Если падает сам `load_config`, чинить **генератор**, а не фикстуру: это ровно тот отказ, ради которого тест написан.

- [ ] **Step 7: Прогнать полный CI-гейт**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```

Expected: все три шага зелёные.

- [ ] **Step 8: Коммит**

```bash
git add ops/access-keys/golden/expected-ws ops/access-keys/test_ws_toml.py \
  bins/outline-ws-rust/src/config/tests/mod.rs
git commit -m "test: pin the generated Android config and load it through the ws-rust loader"
```

---

### Task 7: Документация

**Files:**
- Modify: `ops/access-keys/README.md`
- Modify: `android/README.md`
- Modify: `android/README.ru.md`

**Interfaces:**
- Consumes: всё поведение из задач 1–6.
- Produces: ничего для кода.

- [ ] **Step 1: Обновить `ops/access-keys/README.md`**

В таблице артефактов в начале файла добавить строку:

```markdown
| `<user>.toml` | есть хоть один wire | Конфиг `outline-ws-rust` для Android-клиента |
```

В блоке отчёта добавить строки:

```
written_toml: <путь>                 # если есть хоть один wire
ws_url: https://…/<user>.toml        # ссылка для Android-клиента
warning: …                           # серверная фича выключена — см. ниже
```

Добавить раздел после «⚠️ Порядок outbounds в `.json`»:

```markdown
## Конфиг ws-rust для Android (`<user>.toml`)

Один `[[outline.uplinks]]` на узел из `--node`, внутри — цепочка носителей
через `[[outline.uplinks.fallbacks]]`, все wire'ы заданы share-link'ами (теми
же, что в `<user>.txt`). Порядок цепочки: `vless-xhttp stream-one` →
`vless-ws` → `ss-ws` → `ss-xhttp stream-one` → `vless-xhttp packet-up`.
Отсутствующий путь или кред просто убирает свой wire.

ALPN, в отличие от `.json`, wire'ы не размножает: ws-rust читает первый токен
как запрошенный режим и даунгрейдит носитель внутри wire'а сам
(`ws_h3 → ws_h2 → ws_h1`).

Группа `main` — `active_passive` + `routing_scope = "global"`: один узел несёт
весь трафик, поэтому выходной IP стабилен. `auto_failback` намеренно нет —
уехав на резервный узел, клиент там и остаётся; обратно двигает только
`reselect_interval = "6h"`. `tun_wire_dial = true` обязателен: по умолчанию
он `false`, и тогда каждый TUN-дозвон уходит на wire 0, а цепочка fallback'ов
не работает вовсе.

Три серверные фичи меняют то, что клиент получит, и о каждой генератор
докладывает строкой `warning:`, если она выключена:

| Секция в `config.toml` узла | Что даёт клиенту | Если выключена |
|---|---|---|
| `[session_resumption] enabled` | миграцию живого флоу на смерти носителя | флоу рвётся |
| `[session_resumption] downlink_buffer_bytes` | реплей downstream-хвоста | в мигрировавшем ответе остаётся дыра |
| `[cluster] enabled` | `shared_resume` — мягкую смену активного узла | смена узла рвёт сессии RST |

`[padding]` включается в клиенте, только если узел падит **все** пути этой
цепочки: клиентский переключатель глобальный, а падинг не согласуется по
проводу — падёные кадры на непадёном пути убивают сессию. При частичном
покрытии генератор пишет `enabled = false` и перечисляет непокрытые пути в
`warning:`.
```

- [ ] **Step 2: Обновить `android/README.ru.md`**

Добавить раздел перед «Внешнее управление (`outline://`)»:

```markdown
## Откуда брать конфиг

Узел генерирует готовый конфиг клиента на юзера — `<user>.toml`, рядом с
`.conf` и `.json` (`ops/access-keys/generate_keys.py`, ссылка в отчёте —
`ws_url`). Он несёт полную цепочку носителей на каждый входной узел, failover
между узлами и миграцию живых флоу. Содержимое вставляется в поле **Raw TOML
override** профиля целиком: структурированная форма (`vless://` / `ss://` в
одну строку) описывает один носитель одного узла и цепочку выразить не может.

`[tun] mtu` в конфиге обязан совпадать с `ServerProfile.TUN_MTU` — сейчас
1500. Генератор пишет эту же величину; если менять — менять в обоих местах.
```

- [ ] **Step 3: Обновить `android/README.md`**

Тот же раздел по-английски, перед «External control (`outline://`)»:

```markdown
## Where the config comes from

The node generates a ready client config per user — `<user>.toml`, next to
`.conf` and `.json` (`ops/access-keys/generate_keys.py`; the report prints it
as `ws_url`). It carries the full carrier chain for every entry node, failover
between nodes, and live-flow migration. Paste it whole into the profile's
**Raw TOML override**: the structured form (a single `vless://` / `ss://`
link) describes one carrier of one node and cannot express a chain.

The config's `[tun] mtu` must match `ServerProfile.TUN_MTU` — 1500 today. The
generator emits the same value; change one and you change both.
```

- [ ] **Step 4: Проверить, что документация не разошлась с кодом**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`
Expected: OK (тесты — тот же источник истины, что и таблица фич в README).

- [ ] **Step 5: Коммит**

```bash
git add ops/access-keys/README.md android/README.md android/README.ru.md
git commit -m "docs: describe the ws-rust Android config artifact"
```

---

## Выкладка (после мержа, вручную)

Генератор разворачивается тем же rsync-рецептом, что описан в
`ops/access-keys/README.md`, по одному узлу за раз; рестарт сервисов не нужен —
пишутся файлы, которые nginx уже раздаёт с диска. Флаг `--node` на cloud-узлах
остаётся дефолтным (cloud1+cloud2), на `nuxt` / `nuxt2` — собственный хост.

Первый прогон стоит делать с `--dry-run` и читать `warning:`-строки: на узле
без `[session_resumption]` и без `[cluster]` конфиг сгенерируется, но обещанных
миграций не даст, и это чинится на сервере, а не в клиенте.
