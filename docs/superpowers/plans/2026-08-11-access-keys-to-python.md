# Access-key generation in Python — Implementation Plan (stage 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move access-key generation out of `outline-ss-rust` into a Python package, collapsing the current seven files per user into three — `<user>.conf`, `<user>.json`, `<user>.txt` — with every URI byte-identical to what the binary emits today.

**Architecture:** A package under `ops/access-keys/` parses the node's own `config.toml`, resolves per-user overrides the same way `UserEntry::effective_*` does, and renders artifacts through a URI layer that mirrors `config/access_key.rs` exactly. Equivalence is pinned by a golden corpus captured from the current binary before any porting starts, so the port is written against evidence rather than against a reading of the Rust.

**Tech Stack:** Python 3 stdlib only (`tomllib`, `base64`, `json`, `argparse`, `unittest`) — nodes run 3.12.3, the dev Mac 3.14.5. No third-party packages on production entry nodes.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-08-11-access-keys-to-python-design.md`. This plan covers stage 1 only: the Python package and switching all four nodes. Removing the Rust code is stage 2 and is out of scope here.
- **Python floor:** 3.11 (`tomllib` is stdlib from 3.11). Stdlib only — no `pip install` on cloud1/cloud2/nuxt/nuxt2.
- **URIs must not change by a single byte.** The file layout changes; the links inside do not. Any deviation is a bug, not an improvement.
- **Percent-encoding, exactly:** query values keep `A-Za-z0-9` and `-._~`; fragments keep those plus `:`; everything else becomes `%XX` with **uppercase** hex.
- **ALPN by carrier:** WS and XHTTP `packet-up` get `http/1.1` appended; XHTTP `stream-one` does not (it returns 505 over h1). `h3` is prepended when h3 is enabled *and* has a listen address. With `public_scheme = ws` no `alpn` parameter is emitted at all.
- **h3 is enabled when** (`[server.h3].cert_path` and `.key_path`, each falling back to `[server]`'s pair) are both set, **or** the h3 cert array is non-empty — where `[server.h3].certs` inherits `[server].certs` only if the key is absent entirely; an explicit `certs = []` opts out.
- **Never print `password`, `vless_id` or the control token** to stdout or logs. Generated files contain them by nature; terminal output must not.
- **Commits** run only on the owner's explicit instruction (repository rule). Commit steps are written out but must not be executed until then.
- **Production:** four live nodes. One node at a time, no service restarts — this change only writes files nginx already serves.
- **Language:** code comments and commit messages in English; `ops/*/README.md` in Russian.

---

## File Structure

| File | Responsibility |
|---|---|
| `ops/access-keys/config_model.py` | Create. `config.toml` → `AccessKeyConfig` + resolved `User` list. Owns every `effective_*` fallback and the h3 detection. |
| `ops/access-keys/uri.py` | Create. Encoding primitives, ALPN lists, the six URI builders, `ssconf://`. No file I/O. |
| `ops/access-keys/outline_yaml.py` | Create. The Outline YAML artifact. Separate because it is the one artifact that is not a URI. |
| `ops/access-keys/xray_json.py` | Create. Moved from `ops/xray-json-sub/generate_xray_json.py`, minus its CLI and config parsing (those now live in `config_model` / `generate_keys`). |
| `ops/access-keys/artifacts.py` | Create. Assembles the three per-user files and the `users.txt` report from the layers above. |
| `ops/access-keys/generate_keys.py` | Create. CLI and atomic writes. |
| `ops/access-keys/golden/` | Create. Synthetic `config.toml` plus artifacts captured from the current binary. |
| `ops/access-keys/test_*.py` | Create. One test module per source module, plus the golden comparison. |
| `ops/access-keys/README.md` | Create. Russian, replaces `ops/xray-json-sub/README.md`. |
| `ops/access-keys/nginx-subscription-headers.conf` | Create. Moved from `ops/xray-json-sub/`, widened to `.json` and `.txt`. |
| `ops/xray-json-sub/` | Delete once the new package supersedes it. |
| `ops/provision-node/collect-from-reference.sh:306` | Modify. Learn the new `save-keys.sh` shape. |

The split follows the data flow — parse, render, assemble, write — so each file can be read on its own. `uri.py` is the largest at roughly 200 lines and is the one place where a byte matters; keeping it free of I/O is what makes it testable against the golden corpus.

---

### Task 1: Capture the golden corpus from the current binary

This comes first on purpose. Everything after it is written against recorded
evidence rather than against someone's reading of the Rust, and the corpus stops
being obtainable the moment the Rust code is deleted in stage 2.

**Files:**
- Create: `ops/access-keys/golden/config.toml`
- Create: `ops/access-keys/golden/expected/` (populated by the binary)
- Create: `ops/access-keys/golden/README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: `ops/access-keys/golden/config.toml` and one file per artifact under `golden/expected/`, named exactly as the binary names them.

- [ ] **Step 1: Write the synthetic config**

Create `ops/access-keys/golden/config.toml`. Credentials are fake but
structurally valid; the user set covers every branch the generator has.

```toml
# Synthetic config for the golden corpus. Every credential here is fake.
# Covers: SS-only user, VLESS-only user, both, per-user paths, per-user method,
# a disabled user, and an id that needs sanitising.

[server]
listen = "[::]:443"
cert_path = "/etc/ssl/fake.crt"
key_path = "/etc/ssl/fake.key"

[server.h3]
listen = "[::]:443"

[websocket]
ws_path_tcp = "/GLOBAL/tcp"
ws_path_udp = "/GLOBAL/udp"
ws_path_vless = "/GLOBAL/vless"
ws_path_ss = "/GLOBAL/ss"
xhttp_path_vless = "/GLOBAL/xhttp"
xhttp_path_ss = "/GLOBAL/ssx"

[access_keys]
public_host = "keys.example.com"
public_scheme = "wss"
url_base = "https://keys.example.com/SECRET"
file_extension = ".conf"
print = false

[shadowsocks]
method = "chacha20-ietf-poly1305"

[[users]]
id = "ss-only"
password = "pw-ss-only"

[[users]]
id = "vless-only"
vless_id = "11111111-1111-4111-8111-111111111111"

[[users]]
id = "both"
password = "pw-both"
vless_id = "22222222-2222-4222-8222-222222222222"

[[users]]
id = "own-paths"
password = "pw-own"
vless_id = "33333333-3333-4333-8333-333333333333"
ws_path_vless = "/OWN/vless"
ws_path_ss = "/OWN/ss"
xhttp_path_vless = "/OWN/xhttp"
xhttp_path_ss = "/OWN/ssx"

[[users]]
id = "own-method"
password = "cGFzc3dvcmQtMzItYnl0ZXMtZm9yLTIwMjIta2V5cw=="
method = "2022-blake3-chacha20-poly1305"

[[users]]
id = "disabled"
password = "pw-disabled"
vless_id = "44444444-4444-4444-8444-444444444444"
enabled = false

[[users]]
id = "needs sanitising/1"
password = "pw-sanitise"
vless_id = "55555555-5555-4555-8555-555555555555"
```

- [ ] **Step 2: Build the binary**

Run: `cargo build -p outline-ss-rust`
Expected: `Finished` — a full build, since `target/` was cleaned; allow several minutes.

- [ ] **Step 3: Capture the artifacts**

```bash
mkdir -p ops/access-keys/golden/expected
./target/debug/outline-ss-rust \
  --config ops/access-keys/golden/config.toml \
  --write-access-keys-dir ops/access-keys/golden/expected \
  > ops/access-keys/golden/expected-users.txt
ls ops/access-keys/golden/expected | sort
```

Expected listing — 19 files. Note `disabled` is absent entirely, and
`needs sanitising/1` became `needs_sanitising_1`:

```
both-ss-ws.conf
both-ss-xhttp-packet-up.conf
both-ss-xhttp-stream-one.conf
both-vless-ws.conf
both-vless-xhttp-packet-up.conf
both-vless-xhttp-stream-one.conf
both.conf
needs_sanitising_1-ss-ws.conf
needs_sanitising_1-ss-xhttp-packet-up.conf
needs_sanitising_1-ss-xhttp-stream-one.conf
needs_sanitising_1-vless-ws.conf
needs_sanitising_1-vless-xhttp-packet-up.conf
needs_sanitising_1-vless-xhttp-stream-one.conf
needs_sanitising_1.conf
own-method-ss-ws.conf
own-method-ss-xhttp-packet-up.conf
own-method-ss-xhttp-stream-one.conf
own-method.conf
own-paths-ss-ws.conf
...
```

If the count or names differ from what the binary actually produced, **record
what it produced** — the binary is the reference, not this listing. Update the
expected listing in this plan's Task 6 accordingly.

- [ ] **Step 4: Sanity-check a captured URI**

Run: `grep -o 'alpn=[^&]*' ops/access-keys/golden/expected/both-vless-xhttp-stream-one.conf`
Expected: `alpn=h3%2Ch2` — no `http/1.1`, because `stream-one` bounces on h1.

Run: `grep -o 'alpn=[^&]*' ops/access-keys/golden/expected/both-vless-ws.conf`
Expected: `alpn=h3%2Ch2%2Chttp%2F1.1`

- [ ] **Step 5: Document the corpus**

Create `ops/access-keys/golden/README.md`:

```markdown
# Golden corpus

Снимок артефактов, которые генерирует `outline-ss-rust` на синтетическом
`config.toml` из этого каталога. Все креды фейковые.

Эталон снят с бинаря ДО переноса генерации в Python и служит доказательством
эквивалентности: тесты собирают те же артефакты питоном и сверяют побайтово.

Обновлять эталон можно только вместе с осознанным изменением формата ссылок —
и тогда diff эталона обязан быть в том же коммите, что и правка генератора.

Пересnять:

    cargo build -p outline-ss-rust
    ./target/debug/outline-ss-rust \
      --config ops/access-keys/golden/config.toml \
      --write-access-keys-dir ops/access-keys/golden/expected \
      > ops/access-keys/golden/expected-users.txt
```

- [ ] **Step 6: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/golden
git commit -m "ops(access-keys): capture the golden artifact corpus from the binary"
```

---

### Task 2: Parse config.toml into the access-key config and resolved users

**Files:**
- Create: `ops/access-keys/config_model.py`
- Test: `ops/access-keys/test_config_model.py`

**Interfaces:**
- Consumes: `ops/access-keys/golden/config.toml` as a fixture.
- Produces:
  - `AccessKeys(public_host: str, public_scheme: str, url_base: str | None, file_extension: str, print_report: bool)`
  - `User(name: str, filename: str, password: str | None, method: str, vless_id: str | None, ws_path_tcp: str, ws_path_udp: str, ws_path_vless: str | None, ws_path_ss: str | None, xhttp_path_vless: str | None, xhttp_path_ss: str | None)`
  - `ServerConfig(access_keys: AccessKeys, users: tuple[User, ...], alpn_has_h3: bool)`
  - `load(path: str | Path) -> ServerConfig`
  - `sanitize_filename(value: str) -> str`

- [ ] **Step 1: Write the failing test**

Create `ops/access-keys/test_config_model.py`:

```python
#!/usr/bin/env python3
"""Tests for config_model.py. Stdlib only; no network, no node access."""

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import config_model as cm  # noqa: E402

GOLDEN = HERE / "golden" / "config.toml"


def by_name(server, name):
    return next(u for u in server.users if u.name == name)


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.server = cm.load(GOLDEN)

    def test_reads_the_access_keys_section(self):
        ak = self.server.access_keys
        self.assertEqual(ak.public_host, "keys.example.com")
        self.assertEqual(ak.public_scheme, "wss")
        self.assertEqual(ak.url_base, "https://keys.example.com/SECRET")
        self.assertEqual(ak.file_extension, ".conf")
        self.assertFalse(ak.print_report)

    def test_disabled_user_is_dropped(self):
        self.assertNotIn("disabled", [u.name for u in self.server.users])

    def test_global_paths_apply_when_the_user_has_none(self):
        user = by_name(self.server, "both")
        self.assertEqual(user.ws_path_vless, "/GLOBAL/vless")
        self.assertEqual(user.xhttp_path_ss, "/GLOBAL/ssx")
        self.assertEqual(user.ws_path_tcp, "/GLOBAL/tcp")
        self.assertEqual(user.ws_path_udp, "/GLOBAL/udp")

    def test_per_user_paths_win(self):
        user = by_name(self.server, "own-paths")
        self.assertEqual(user.ws_path_vless, "/OWN/vless")
        self.assertEqual(user.ws_path_ss, "/OWN/ss")
        self.assertEqual(user.xhttp_path_vless, "/OWN/xhttp")
        self.assertEqual(user.xhttp_path_ss, "/OWN/ssx")

    def test_method_falls_back_to_the_shadowsocks_section(self):
        self.assertEqual(by_name(self.server, "both").method, "chacha20-ietf-poly1305")

    def test_per_user_method_wins(self):
        self.assertEqual(
            by_name(self.server, "own-method").method, "2022-blake3-chacha20-poly1305"
        )

    def test_filename_is_sanitised(self):
        self.assertEqual(by_name(self.server, "needs sanitising/1").filename, "needs_sanitising_1")

    def test_h3_is_on_because_the_h3_table_inherits_the_tcp_certs(self):
        # [server.h3] sets only `listen`; its cert array is absent, so it
        # inherits [server]'s pair. That is what puts h3 in the ALPN list.
        self.assertTrue(self.server.alpn_has_h3)


class SanitizeTest(unittest.TestCase):
    def test_keeps_safe_characters(self):
        self.assertEqual(cm.sanitize_filename("a.b_c-1"), "a.b_c-1")

    def test_replaces_everything_else(self):
        self.assertEqual(cm.sanitize_filename("a/b c:d"), "a_b_c_d")

    def test_empty_becomes_user(self):
        self.assertEqual(cm.sanitize_filename(""), "user")


class H3DetectionTest(unittest.TestCase):
    def load_text(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(text, encoding="utf-8")
            return cm.load(path)

    BASE = """
[access_keys]
public_host = "h"

[[users]]
id = "u"
password = "p"
"""

    def test_no_h3_table_means_no_h3(self):
        server = self.load_text('[server]\nlisten = ":443"\ncert_path = "c"\nkey_path = "k"\n' + self.BASE)
        self.assertFalse(server.alpn_has_h3)

    def test_h3_listen_without_any_cert_means_no_h3(self):
        server = self.load_text('[server]\nlisten = ":443"\n[server.h3]\nlisten = ":443"\n' + self.BASE)
        self.assertFalse(server.alpn_has_h3)

    def test_explicit_empty_cert_array_opts_out_of_inheritance(self):
        text = (
            '[server]\nlisten = ":443"\n'
            '[[server.certs]]\ncert_path = "c"\nkey_path = "k"\n'
            "[server.h3]\nlisten = \":443\"\ncerts = []\n" + self.BASE
        )
        self.assertFalse(self.load_text(text).alpn_has_h3)

    def test_h3_certs_absent_inherits_the_tcp_array(self):
        text = (
            '[server]\nlisten = ":443"\n'
            '[[server.certs]]\ncert_path = "c"\nkey_path = "k"\n'
            '[server.h3]\nlisten = ":443"\n' + self.BASE
        )
        self.assertTrue(self.load_text(text).alpn_has_h3)

    def test_h3_enabled_but_no_listen_means_no_h3_in_alpn(self):
        text = '[server]\nlisten = ":443"\ncert_path = "c"\nkey_path = "k"\n[server.h3]\n' + self.BASE
        self.assertFalse(self.load_text(text).alpn_has_h3)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/access-keys/test_config_model.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'config_model'`

- [ ] **Step 3: Write the implementation**

Create `ops/access-keys/config_model.py`:

```python
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
from pathlib import Path

DEFAULT_METHOD = "chacha20-ietf-poly1305"
DEFAULT_SCHEME = "wss"
DEFAULT_EXTENSION = ".yaml"


@dataclass(frozen=True)
class AccessKeys:
    public_host: str
    public_scheme: str
    url_base: str | None
    file_extension: str
    print_report: bool


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
class ServerConfig:
    access_keys: AccessKeys
    users: tuple[User, ...]
    alpn_has_h3: bool


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


def load(path: str | Path) -> ServerConfig:
    with open(path, "rb") as handle:
        raw = tomllib.load(handle)

    server = raw.get("server", {})
    websocket = raw.get("websocket", {})
    ak_section = raw.get("access_keys", {})

    public_host = ak_section.get("public_host")
    if not public_host:
        raise SystemExit(f"{path}: [access_keys] public_host is required")

    access_keys = AccessKeys(
        public_host=public_host,
        public_scheme=ak_section.get("public_scheme") or DEFAULT_SCHEME,
        url_base=ak_section.get("url_base"),
        file_extension=ak_section.get("file_extension") or DEFAULT_EXTENSION,
        print_report=bool(ak_section.get("print", False)),
    )
    if access_keys.public_scheme not in ("ws", "wss"):
        raise SystemExit(f"{path}: public_scheme must be either \"ws\" or \"wss\"")

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

    return ServerConfig(
        access_keys=access_keys, users=tuple(users), alpn_has_h3=_h3_in_alpn(server)
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/access-keys/test_config_model.py -v`
Expected: PASS — `Ran 16 tests`, `OK`

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/config_model.py ops/access-keys/test_config_model.py
git commit -m "ops(access-keys): parse config.toml into access-key config and resolved users"
```

---

### Task 3: Encoding primitives

**Files:**
- Create: `ops/access-keys/uri.py`
- Test: `ops/access-keys/test_uri.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `percent_encode_query_value(value: str) -> str`, `percent_encode_fragment(value: str) -> str`, `normalize_path(path: str) -> str`, `normalize_host(host: str) -> str`, `authority_with_default_port(host: str, default_port: int) -> str`, `host_short_label(host: str) -> str`, `carrier_label(host: str, user_id: str, transport: str) -> str`, `join_url(base: str, suffix: str) -> str`, `ssconf_url(config_url: str) -> str`, `ss_userinfo(method: str, password: str) -> str`, `yaml_quote(value: str) -> str`.

- [ ] **Step 1: Write the failing test**

Create `ops/access-keys/test_uri.py`:

```python
#!/usr/bin/env python3
"""Tests for uri.py. Vectors are taken from access_key.rs behaviour."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uri  # noqa: E402


class PercentEncodeTest(unittest.TestCase):
    def test_query_keeps_unreserved(self):
        self.assertEqual(uri.percent_encode_query_value("aZ0-._~"), "aZ0-._~")

    def test_query_encodes_slash_and_comma_uppercase_hex(self):
        self.assertEqual(uri.percent_encode_query_value("/a,b"), "%2Fa%2Cb")

    def test_query_encodes_colon(self):
        self.assertEqual(uri.percent_encode_query_value("a:b"), "a%3Ab")

    def test_fragment_keeps_colon(self):
        self.assertEqual(uri.percent_encode_fragment("host:user"), "host%3Auser".replace("%3A", ":"))

    def test_fragment_encodes_space(self):
        self.assertEqual(uri.percent_encode_fragment("a b"), "a%20b")

    def test_non_ascii_is_encoded_per_utf8_byte(self):
        self.assertEqual(uri.percent_encode_query_value("é"), "%C3%A9")


class NormalizeTest(unittest.TestCase):
    def test_path_gets_a_leading_slash(self):
        self.assertEqual(uri.normalize_path("a/b"), "/a/b")

    def test_path_already_absolute_is_untouched(self):
        self.assertEqual(uri.normalize_path("/a/b"), "/a/b")

    def test_plain_host_untouched(self):
        self.assertEqual(uri.normalize_host("example.com"), "example.com")

    def test_bracketed_host_untouched(self):
        self.assertEqual(uri.normalize_host("[::1]:443"), "[::1]:443")

    def test_bare_ipv6_gets_brackets(self):
        self.assertEqual(uri.normalize_host("::1"), "[::1]")

    def test_ipv6_with_port_gets_brackets_around_the_address(self):
        self.assertEqual(uri.normalize_host("::1:443"), "[::1]:443")


class AuthorityTest(unittest.TestCase):
    def test_appends_the_default_port(self):
        self.assertEqual(uri.authority_with_default_port("example.com", 443), "example.com:443")

    def test_keeps_an_explicit_port(self):
        self.assertEqual(uri.authority_with_default_port("example.com:8443", 443), "example.com:8443")


class LabelTest(unittest.TestCase):
    def test_short_label_takes_the_first_component(self):
        self.assertEqual(uri.host_short_label("cloud.beerloga.su"), "cloud")

    def test_short_label_keeps_a_bare_ip(self):
        self.assertEqual(uri.host_short_label("198.51.100.7"), "198.51.100.7")

    def test_carrier_label_shape(self):
        self.assertEqual(
            uri.carrier_label("cloud.beerloga.su", "bob", "vless-ws"), "cloud:bob-vless-ws"
        )


class UrlTest(unittest.TestCase):
    def test_join_trims_the_trailing_slash(self):
        self.assertEqual(uri.join_url("https://h/base/", "x.conf"), "https://h/base/x.conf")

    def test_join_rejects_a_non_http_base(self):
        with self.assertRaises(ValueError):
            uri.join_url("ftp://h", "x.conf")

    def test_ssconf_replaces_https(self):
        self.assertEqual(uri.ssconf_url("https://h/x.conf"), "ssconf://h/x.conf")

    def test_ssconf_replaces_http(self):
        self.assertEqual(uri.ssconf_url("http://h/x.conf"), "ssconf://h/x.conf")

    def test_ssconf_is_idempotent(self):
        self.assertEqual(uri.ssconf_url("ssconf://h/x.conf"), "ssconf://h/x.conf")


class MiscTest(unittest.TestCase):
    def test_ss_userinfo_is_urlsafe_base64_without_padding(self):
        # base64("aes-128-gcm:pw") == "YWVzLTEyOC1nY206cHc=" -> padding stripped
        self.assertEqual(uri.ss_userinfo("aes-128-gcm", "pw"), "YWVzLTEyOC1nY206cHc")

    def test_yaml_quote_escapes_backslash_and_quote(self):
        self.assertEqual(uri.yaml_quote('a"b\\c'), '"a\\"b\\\\c"')


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/access-keys/test_uri.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'uri'`

- [ ] **Step 3: Write the implementation**

Create `ops/access-keys/uri.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/access-keys/test_uri.py -v`
Expected: PASS — `Ran 22 tests`, `OK`

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/uri.py ops/access-keys/test_uri.py
git commit -m "ops(access-keys): port the URI encoding primitives"
```

---

### Task 4: ALPN lists and the six URI builders

**Files:**
- Modify: `ops/access-keys/uri.py`
- Test: `ops/access-keys/test_uri.py`

**Interfaces:**
- Consumes: everything from Task 3.
- Produces:
  - `alpn_list(scheme: str, has_h3: bool, carrier: str) -> str | None` where `carrier` is one of `"ws"`, `"packet-up"`, `"stream-one"`
  - `vless_ws_uri(vless_id, host, scheme, path, label, alpn) -> str`
  - `vless_xhttp_uri(vless_id, host, scheme, path, label, mode, alpn) -> str`
  - `ss_ws_uri(method, password, host, scheme, path, label, alpn) -> str`
  - `ss_xhttp_uri(method, password, host, scheme, path, label, mode, alpn) -> str`

  `label` is the bare user id; the builders wrap it with `carrier_label`. `mode` is `"packet-up"` or `"stream-one"`. `alpn` is the string from `alpn_list` or `None`.

- [ ] **Step 1: Write the failing test**

Append to `ops/access-keys/test_uri.py`, before the `if __name__` block:

```python
class AlpnTest(unittest.TestCase):
    def test_ws_with_h3(self):
        self.assertEqual(uri.alpn_list("wss", True, "ws"), "h3,h2,http/1.1")

    def test_ws_without_h3(self):
        self.assertEqual(uri.alpn_list("wss", False, "ws"), "h2,http/1.1")

    def test_packet_up_keeps_http11(self):
        self.assertEqual(uri.alpn_list("wss", True, "packet-up"), "h3,h2,http/1.1")

    def test_stream_one_drops_http11(self):
        # stream-one returns 505 over h1, so offering it would invite a dial
        # that bounces immediately.
        self.assertEqual(uri.alpn_list("wss", True, "stream-one"), "h3,h2")

    def test_stream_one_without_h3(self):
        self.assertEqual(uri.alpn_list("wss", False, "stream-one"), "h2")

    def test_plain_ws_scheme_emits_no_alpn(self):
        # ALPN is a TLS extension; on ws:// it would be noise.
        self.assertIsNone(uri.alpn_list("ws", True, "ws"))


class BuilderTest(unittest.TestCase):
    HOST = "keys.example.com"
    UUID = "11111111-1111-4111-8111-111111111111"

    def test_vless_ws(self):
        self.assertEqual(
            uri.vless_ws_uri(self.UUID, self.HOST, "wss", "/GLOBAL/vless", "bob", "h3,h2,http/1.1"),
            "vless://11111111-1111-4111-8111-111111111111@keys.example.com:443"
            "?type=ws&security=tls&alpn=h3%2Ch2%2Chttp%2F1.1&path=%2FGLOBAL%2Fvless"
            "&encryption=none#keys:bob-vless-ws",
        )

    def test_vless_xhttp_stream_one(self):
        self.assertEqual(
            uri.vless_xhttp_uri(
                self.UUID, self.HOST, "wss", "/GLOBAL/xhttp", "bob", "stream-one", "h3,h2"
            ),
            "vless://11111111-1111-4111-8111-111111111111@keys.example.com:443"
            "?type=xhttp&mode=stream-one&security=tls&alpn=h3%2Ch2&path=%2FGLOBAL%2Fxhttp"
            "&encryption=none#keys:bob-vless-xhttp-stream-one",
        )

    def test_ss_ws(self):
        self.assertEqual(
            uri.ss_ws_uri("aes-128-gcm", "pw", self.HOST, "wss", "/GLOBAL/ss", "bob", "h2,http/1.1"),
            "ss://YWVzLTEyOC1nY206cHc@keys.example.com:443"
            "?type=ws&security=tls&alpn=h2%2Chttp%2F1.1&path=%2FGLOBAL%2Fss#keys:bob-ss-ws",
        )

    def test_ss_xhttp_packet_up_omits_alpn_when_it_is_none(self):
        # `alpn=None` with a wss scheme is not something the assembler does;
        # it is here to prove the parameter disappears entirely rather than
        # being rendered as the string "None". `security` stays tls.
        self.assertEqual(
            uri.ss_xhttp_uri(
                "aes-128-gcm", "pw", self.HOST, "wss", "/GLOBAL/ssx", "bob", "packet-up", None
            ),
            "ss://YWVzLTEyOC1nY206cHc@keys.example.com:443"
            "?type=xhttp&mode=packet-up&security=tls&path=%2FGLOBAL%2Fssx"
            "#keys:bob-ss-xhttp-packet-up",
        )

    def test_plain_scheme_flips_security_and_port(self):
        self.assertTrue(
            uri.vless_ws_uri(self.UUID, self.HOST, "ws", "/p", "bob", None).startswith(
                "vless://11111111-1111-4111-8111-111111111111@keys.example.com:80?type=ws&security=none&path="
            )
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/access-keys/test_uri.py -v`
Expected: FAIL — `AttributeError: module 'uri' has no attribute 'alpn_list'`

- [ ] **Step 3: Write the implementation**

Append to `ops/access-keys/uri.py`:

```python
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
    method: str, password: str, host: str, scheme: str, path: str, label: str, alpn: str | None
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/access-keys/test_uri.py -v`
Expected: PASS — `Ran 33 tests`, `OK`

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/uri.py ops/access-keys/test_uri.py
git commit -m "ops(access-keys): port the ALPN lists and the six URI builders"
```

---

### Task 5: Outline YAML artifact

**Files:**
- Create: `ops/access-keys/outline_yaml.py`
- Test: `ops/access-keys/test_outline_yaml.py`

**Interfaces:**
- Consumes: `uri.yaml_quote`, `uri.normalize_host`, `uri.normalize_path` from Task 3.
- Produces: `websocket_url(scheme: str, host: str, path: str) -> str`, `render(method: str, password: str, tcp_url: str, udp_url: str) -> str`.

- [ ] **Step 1: Write the failing test**

Create `ops/access-keys/test_outline_yaml.py`:

```python
#!/usr/bin/env python3
"""Tests for outline_yaml.py, checked against the golden corpus."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import outline_yaml  # noqa: E402

GOLDEN_DIR = HERE / "golden" / "expected"


class WebsocketUrlTest(unittest.TestCase):
    def test_builds_a_wss_url(self):
        self.assertEqual(
            outline_yaml.websocket_url("wss", "keys.example.com", "/GLOBAL/tcp"),
            "wss://keys.example.com/GLOBAL/tcp",
        )

    def test_adds_the_leading_slash(self):
        self.assertEqual(
            outline_yaml.websocket_url("wss", "keys.example.com", "GLOBAL/tcp"),
            "wss://keys.example.com/GLOBAL/tcp",
        )


class RenderTest(unittest.TestCase):
    def test_matches_the_golden_outline_artifact(self):
        expected = (GOLDEN_DIR / "both.conf").read_text(encoding="utf-8")
        actual = outline_yaml.render(
            "chacha20-ietf-poly1305",
            "pw-both",
            "wss://keys.example.com/GLOBAL/tcp",
            "wss://keys.example.com/GLOBAL/udp",
        )
        self.assertEqual(actual, expected)

    def test_quotes_are_escaped(self):
        rendered = outline_yaml.render('a"b', "p", "u", "u")
        self.assertIn('cipher: "a\\"b"', rendered)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/access-keys/test_outline_yaml.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'outline_yaml'`

- [ ] **Step 3: Write the implementation**

Create `ops/access-keys/outline_yaml.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/access-keys/test_outline_yaml.py -v`
Expected: PASS — `Ran 4 tests`, `OK`

If `test_matches_the_golden_outline_artifact` fails, the diff is authoritative:
the golden file came from the binary. Fix `render`, never the golden file.

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/outline_yaml.py ops/access-keys/test_outline_yaml.py
git commit -m "ops(access-keys): port the Outline YAML artifact"
```

---

### Task 6: Assemble artifacts and prove equivalence against the golden corpus

This is the task that justifies the whole plan: it reproduces every artifact the
binary emits and compares byte for byte.

**Files:**
- Create: `ops/access-keys/artifacts.py`
- Test: `ops/access-keys/test_artifacts.py`

**Interfaces:**
- Consumes: `config_model.load`, `config_model.User`, `config_model.AccessKeys`, everything in `uri`, `outline_yaml.render` / `websocket_url`.
- Produces:
  - `Artifact(name: str, content: str)` — `name` is the binary's file name without extension logic applied by the caller, e.g. `both-vless-ws`; `content` ends with `\n`.
  - `legacy_artifacts(user: User, ak: AccessKeys, has_h3: bool) -> list[Artifact]` — exactly what the binary writes, in the binary's order. Used by the golden test and by the node-side comparison; not written to disk.
  - `user_urls(user: User, ak: AccessKeys, has_h3: bool) -> list[str]` — the lines of `<user>.txt`.
  - `outline_artifact(user: User, ak: AccessKeys) -> str | None` — the `<user>.conf` body.
  - `config_url(user: User, ak: AccessKeys) -> str | None`, `access_key_url(user: User, ak: AccessKeys) -> str | None`.

- [ ] **Step 1: Write the failing test**

Create `ops/access-keys/test_artifacts.py`:

```python
#!/usr/bin/env python3
"""Golden comparison: Python must reproduce the binary's artifacts exactly."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import artifacts  # noqa: E402
import config_model as cm  # noqa: E402

GOLDEN = HERE / "golden" / "config.toml"
EXPECTED = HERE / "golden" / "expected"


def golden_files():
    return sorted(p.name for p in EXPECTED.iterdir() if p.is_file())


class GoldenTest(unittest.TestCase):
    def setUp(self):
        self.server = cm.load(GOLDEN)
        self.ak = self.server.access_keys
        self.produced = {}
        for user in self.server.users:
            for artifact in artifacts.legacy_artifacts(user, self.ak, self.server.alpn_has_h3):
                self.produced[artifact.name + self.ak.file_extension] = artifact.content

    def test_produces_exactly_the_same_file_names(self):
        self.assertEqual(sorted(self.produced), golden_files())

    def test_every_file_matches_byte_for_byte(self):
        for name in golden_files():
            with self.subTest(artifact=name):
                self.assertEqual(
                    self.produced[name], (EXPECTED / name).read_text(encoding="utf-8")
                )


class UserUrlsTest(unittest.TestCase):
    def setUp(self):
        self.server = cm.load(GOLDEN)
        self.ak = self.server.access_keys

    def user(self, name):
        return next(u for u in self.server.users if u.name == name)

    def test_txt_starts_with_ssconf_then_lists_every_uri(self):
        lines = artifacts.user_urls(self.user("both"), self.ak, self.server.alpn_has_h3)
        self.assertTrue(lines[0].startswith("ssconf://"))
        self.assertEqual(len(lines), 7)
        self.assertEqual(
            [line.split("#", 1)[1] for line in lines[1:]],
            [
                "keys:both-ss-ws",
                "keys:both-ss-xhttp-packet-up",
                "keys:both-ss-xhttp-stream-one",
                "keys:both-vless-ws",
                "keys:both-vless-xhttp-packet-up",
                "keys:both-vless-xhttp-stream-one",
            ],
        )

    def test_txt_lines_are_exactly_the_legacy_uris(self):
        # The .txt file must be a repackaging, never a re-rendering.
        user = self.user("own-paths")
        legacy = artifacts.legacy_artifacts(user, self.ak, self.server.alpn_has_h3)
        uris = [a.content.rstrip("\n") for a in legacy if a.content.startswith(("ss://", "vless://"))]
        lines = artifacts.user_urls(user, self.ak, self.server.alpn_has_h3)
        self.assertEqual(lines[1:], uris)

    def test_vless_only_user_has_no_ssconf_line(self):
        lines = artifacts.user_urls(self.user("vless-only"), self.ak, self.server.alpn_has_h3)
        self.assertFalse(any(line.startswith("ssconf://") for line in lines))
        self.assertEqual(len(lines), 3)

    def test_ss_only_user_has_no_vless_lines(self):
        lines = artifacts.user_urls(self.user("ss-only"), self.ak, self.server.alpn_has_h3)
        self.assertFalse(any("vless" in line for line in lines))


class UrlHelpersTest(unittest.TestCase):
    def setUp(self):
        self.server = cm.load(GOLDEN)
        self.ak = self.server.access_keys
        self.user = next(u for u in self.server.users if u.name == "both")

    def test_config_url_uses_the_sanitised_filename(self):
        self.assertEqual(
            artifacts.config_url(self.user, self.ak),
            "https://keys.example.com/SECRET/both.conf",
        )

    def test_access_key_url_is_the_ssconf_form(self):
        self.assertEqual(
            artifacts.access_key_url(self.user, self.ak),
            "ssconf://keys.example.com/SECRET/both.conf",
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/access-keys/test_artifacts.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'artifacts'`

- [ ] **Step 3: Write the implementation**

Create `ops/access-keys/artifacts.py`:

```python
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
from config_model import AccessKeys, User


@dataclass(frozen=True)
class Artifact:
    name: str
    content: str


def config_url(user: User, ak: AccessKeys) -> str | None:
    if not ak.url_base or user.password is None:
        return None
    return uri.join_url(ak.url_base, f"{user.filename}{ak.file_extension}")


def access_key_url(user: User, ak: AccessKeys) -> str | None:
    url = config_url(user, ak)
    return uri.ssconf_url(url) if url else None


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
    ssconf = access_key_url(user, ak)
    if ssconf:
        lines.append(ssconf)
    lines.extend(
        artifact.content.rstrip("\n")
        for artifact in legacy_artifacts(user, ak, has_h3)
        if artifact.content.startswith(("ss://", "vless://"))
    )
    return lines
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/access-keys/test_artifacts.py -v`
Expected: PASS — `Ran 8 tests`, `OK`, with `test_every_file_matches_byte_for_byte` reporting a subtest per artifact.

A failure here means the port diverges from the binary. Read the diff, fix the
Python, and never touch `golden/expected`.

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/artifacts.py ops/access-keys/test_artifacts.py
git commit -m "ops(access-keys): assemble artifacts and pin them to the golden corpus"
```

---

### Task 7: Move the Xray-JSON generator into the package

**Files:**
- Create: `ops/access-keys/xray_json.py`
- Test: `ops/access-keys/test_xray_json.py`
- Delete: `ops/xray-json-sub/generate_xray_json.py`, `ops/xray-json-sub/test_generate_xray_json.py`

**Interfaces:**
- Consumes: `config_model.User` (which now carries `ws_path_vless` / `xhttp_path_vless`).
- Produces: `DEFAULT_NODES: tuple[str, ...]`, `node_tag(node) -> str`, `build_outbounds(vless_id, xhttp_path, ws_path, nodes) -> list[dict]`, `build_config(user, nodes) -> dict`, `BALANCER_TAG`, `PING_DESTINATION`, `PRIVATE_CIDRS`.

- [ ] **Step 1: Copy the module and drop its config layer**

```bash
git mv ops/xray-json-sub/generate_xray_json.py ops/access-keys/xray_json.py
git mv ops/xray-json-sub/test_generate_xray_json.py ops/access-keys/test_xray_json.py
```

Then edit `ops/access-keys/xray_json.py`: delete `load_users`, `main`,
`write_subscription`, `DEFAULT_CONFIG`, `DEFAULT_OUT_DIR`, the `User` dataclass,
the `if __name__ == "__main__"` block and the now-unused `argparse` / `json` /
`os` / `sys` / `tomllib` / `Path` imports. Keep `build_outbounds`,
`build_config`, `node_tag`, `_tls_settings`, `_vless_outbound`, `DEFAULT_NODES`,
`PORT`, `BALANCER_TAG`, `PING_DESTINATION`, `PRIVATE_CIDRS`. Add at the top:

```python
from config_model import User  # noqa: F401  (build_config's parameter type)
```

**Then fix the field names.** The old module's `User` carried `xhttp_path` and
`ws_path`; the shared model spells them out per protocol, because it also has to
describe the SS paths. Inside `build_config`, replace:

```python
        "outbounds": build_outbounds(
            user.vless_id, user.xhttp_path, user.ws_path, nodes
        ),
```

with:

```python
        "outbounds": build_outbounds(
            user.vless_id, user.xhttp_path_vless, user.ws_path_vless, nodes
        ),
```

Missing this is not a subtle failure — `build_config` raises `AttributeError`
on the first user.

- [ ] **Step 2: Point the tests at the shared model**

In `ops/access-keys/test_xray_json.py`: replace `import generate_xray_json as gen`
with `import xray_json as gen`, delete the `LoadUsersTest` class and the
`WriteAndMainTest` class along with `CONFIG_TOML`, `write_config` and `load`
(those behaviours now belong to `config_model` and `generate_keys`), and build
users through the shared dataclass:

```python
from config_model import User

def make_user(name="alice", xhttp="/OTHER/xhttp", ws="/SECRET/vless"):
    return User(
        name=name,
        filename=name,
        password=None,
        method="chacha20-ietf-poly1305",
        vless_id=UUID,
        ws_path_tcp="/t",
        ws_path_udp="/u",
        ws_path_vless=ws,
        ws_path_ss=None,
        xhttp_path_vless=xhttp,
        xhttp_path_ss=None,
    )
```

and replace every `gen.User(...)` construction in `BuildConfigTest` with
`make_user(...)`.

- [ ] **Step 3: Run the moved tests**

Run: `python3 ops/access-keys/test_xray_json.py -v`
Expected: PASS — the outbound, ALPN, routing, balancer and observatory tests
survive the move; `Ran 21 tests`, `OK`.

- [ ] **Step 4: Remove the old directory**

```bash
git mv ops/xray-json-sub/nginx-subscription-headers.conf ops/access-keys/nginx-subscription-headers.conf
git rm -q ops/xray-json-sub/README.md
rmdir ops/xray-json-sub 2>/dev/null || true
ls ops/xray-json-sub 2>&1
```

Expected: `No such file or directory`

- [ ] **Step 5: Commit** *(only after the owner explicitly asks)*

```bash
git add -A ops/access-keys ops/xray-json-sub
git commit -m "ops(access-keys): move the Xray-JSON generator into the package"
```

---

### Task 8: CLI — write three files per user plus the report

**Files:**
- Create: `ops/access-keys/generate_keys.py`
- Test: `ops/access-keys/test_generate_keys.py`

**Interfaces:**
- Consumes: everything from Tasks 2–7.
- Produces: `DEFAULT_CONFIG: str`, `DEFAULT_OUT_DIR: str`, `write_atomic(path: Path, content: str) -> None`, `render_report(written: list[dict]) -> str`, `main(argv: Sequence[str] | None = None) -> int`. CLI flags: `--config`, `--out-dir`, `--node` (repeatable), `--dry-run`.

- [ ] **Step 1: Write the failing test**

Create `ops/access-keys/test_generate_keys.py`:

```python
#!/usr/bin/env python3
"""Tests for the CLI: three files per user, atomic writes, the report."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import generate_keys as gk  # noqa: E402

GOLDEN = HERE / "golden" / "config.toml"


def run(out_dir, *extra):
    return gk.main(["--config", str(GOLDEN), "--out-dir", str(out_dir), *extra])


class MainTest(unittest.TestCase):
    def test_writes_three_files_for_a_user_with_both_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(run(out), 0)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("both"))
        self.assertEqual(names, ["both.conf", "both.json", "both.txt"])

    def test_ss_only_user_gets_no_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("ss-only"))
        self.assertEqual(names, ["ss-only.conf", "ss-only.txt"])

    def test_vless_only_user_gets_no_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("vless-only"))
        self.assertEqual(names, ["vless-only.json", "vless-only.txt"])

    def test_disabled_user_gets_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = [p.name for p in out.iterdir() if p.name.startswith("disabled")]
        self.assertEqual(names, [])

    def test_no_legacy_per_carrier_files_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = [p.name for p in out.iterdir()]
        self.assertFalse([n for n in names if "-vless-ws" in n or "-ss-xhttp-" in n])

    def test_txt_content_matches_the_artifact_layer(self):
        import artifacts
        import config_model as cm

        server = cm.load(GOLDEN)
        user = next(u for u in server.users if u.name == "both")
        expected = "\n".join(artifacts.user_urls(user, server.access_keys, server.alpn_has_h3)) + "\n"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            actual = (out / "both.txt").read_text(encoding="utf-8")
        self.assertEqual(actual, expected)

    def test_json_is_a_single_element_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            payload = json.loads((out / "both.json").read_text(encoding="utf-8"))
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["outbounds"][0]["tag"], "cloud1-xhttp-h3")

    def test_files_are_world_readable_with_no_temp_left_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            self.assertEqual(os.stat(out / "both.conf").st_mode & 0o777, 0o644)
            self.assertFalse([p.name for p in out.iterdir() if p.name.startswith(".")])

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(run(out, "--dry-run"), 0)
            self.assertEqual(list(out.iterdir()), [])

    def test_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            first = (out / "both.txt").read_text(encoding="utf-8")
            run(out)
            self.assertEqual((out / "both.txt").read_text(encoding="utf-8"), first)


class ReportTest(unittest.TestCase):
    def test_report_has_one_block_per_user(self):
        report = gk.render_report(
            [
                {
                    "user": "both",
                    "conf": "/out/both.conf",
                    "json": "/out/both.json",
                    "txt": "/out/both.txt",
                    "config_url": "https://h/SECRET/both.conf",
                    "access_key_url": "ssconf://h/SECRET/both.conf",
                }
            ]
        )
        self.assertEqual(
            report,
            "user: both\n"
            "written_conf: /out/both.conf\n"
            "written_json: /out/both.json\n"
            "written_txt: /out/both.txt\n"
            "config_url: https://h/SECRET/both.conf\n"
            "access_key_url: ssconf://h/SECRET/both.conf\n",
        )

    def test_absent_fields_are_omitted(self):
        report = gk.render_report([{"user": "v", "json": "/out/v.json", "txt": "/out/v.txt"}])
        self.assertEqual(report, "user: v\nwritten_json: /out/v.json\nwritten_txt: /out/v.txt\n")

    def test_blocks_are_separated_by_a_blank_line(self):
        report = gk.render_report([{"user": "a", "txt": "/a.txt"}, {"user": "b", "txt": "/b.txt"}])
        self.assertEqual(report, "user: a\nwritten_txt: /a.txt\n\nuser: b\nwritten_txt: /b.txt\n")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 ops/access-keys/test_generate_keys.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'generate_keys'`

- [ ] **Step 3: Write the implementation**

Create `ops/access-keys/generate_keys.py`:

```python
#!/usr/bin/env python3
"""Write the access-key artifacts for every user in a node's config.toml.

Three files per user: <user>.conf (Outline), <user>.json (Xray subscription
balanced across the cloud entry nodes) and <user>.txt (every URL, one per line).
The report goes to stdout; save-keys.sh redirects it into users.txt.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import artifacts
import config_model
import xray_json

DEFAULT_CONFIG = "/opt/outline/outline-ss-rust/config.toml"
DEFAULT_OUT_DIR = "/var/www/html/<keys-dir>"

_REPORT_FIELDS = (
    ("conf", "written_conf"),
    ("json", "written_json"),
    ("txt", "written_txt"),
    ("config_url", "config_url"),
    ("access_key_url", "access_key_url"),
)


def write_atomic(path: Path, content: str) -> None:
    """Write via a temp file so a client never reads a half-written artifact."""
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def render_report(written: Sequence[dict]) -> str:
    blocks = []
    for record in written:
        lines = [f"user: {record['user']}"]
        lines.extend(
            f"{label}: {record[key]}" for key, label in _REPORT_FIELDS if record.get(key)
        )
        blocks.append("".join(f"{line}\n" for line in lines))
    return "\n".join(blocks)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate access-key artifacts.")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="outline-ss-rust config.toml")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR, help="where artifacts are written")
    parser.add_argument(
        "--node",
        action="append",
        dest="nodes",
        help="entry node for the Xray balancer; repeat for each. Default: %s"
        % ", ".join(xray_json.DEFAULT_NODES),
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="render everything but write nothing"
    )
    args = parser.parse_args(argv)

    nodes = tuple(args.nodes) if args.nodes else xray_json.DEFAULT_NODES
    server = config_model.load(args.config)
    if not server.users:
        raise SystemExit(f"{args.config}: no enabled users")

    out_dir = Path(args.out_dir)
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    ak = server.access_keys
    written: list[dict] = []
    for user in server.users:
        record: dict = {"user": user.name}

        outline = artifacts.outline_artifact(user, ak)
        if outline is not None:
            target = out_dir / f"{user.filename}{ak.file_extension}"
            if not args.dry_run:
                write_atomic(target, outline)
            record["conf"] = str(target)

        if user.vless_id and (user.ws_path_vless or user.xhttp_path_vless):
            document = xray_json.build_config(user, nodes)
            target = out_dir / f"{user.filename}.json"
            if not args.dry_run:
                write_atomic(target, json.dumps([document], indent=2, ensure_ascii=False) + "\n")
            record["json"] = str(target)

        urls = artifacts.user_urls(user, ak, server.alpn_has_h3)
        if urls:
            target = out_dir / f"{user.filename}.txt"
            if not args.dry_run:
                write_atomic(target, "\n".join(urls) + "\n")
            record["txt"] = str(target)

        record["config_url"] = artifacts.config_url(user, ak)
        record["access_key_url"] = artifacts.access_key_url(user, ak)
        written.append(record)

    # Never a credential: paths and counts only.
    print(render_report(written), end="")
    print(f"\n{len(written)} user(s), {len(nodes)} balancer node(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 ops/access-keys/test_generate_keys.py -v`
Expected: PASS — `Ran 13 tests`, `OK`

- [ ] **Step 5: Run the whole suite together**

Run: `python3 -m unittest discover -s ops/access-keys -p "test_*.py" -v 2>&1 | tail -3`
Expected: `OK`, with the total across all five modules.

- [ ] **Step 6: Make the entry point executable**

```bash
chmod +x ops/access-keys/generate_keys.py
```

- [ ] **Step 7: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/generate_keys.py ops/access-keys/test_generate_keys.py
git commit -m "ops(access-keys): write three artifacts per user from one CLI"
```

---

### Task 9: README and the nginx header widening

**Files:**
- Create: `ops/access-keys/README.md`
- Modify: `ops/access-keys/nginx-subscription-headers.conf`

**Interfaces:**
- Consumes: the CLI from Task 8.
- Produces: no code.

- [ ] **Step 1: Widen the nginx location to cover `.txt`**

`<user>.txt` is a subscription too — a plain list of URIs — so it should carry
the same headers as `<user>.json`. Edit
`ops/access-keys/nginx-subscription-headers.conf`, replacing the location line:

```nginx
location ~ ^/<keys-prefix>/[^/]+\.(json|txt)$ {
```

and add to the comment block above it:

```
# Applies to both subscription forms: <user>.json (Xray-JSON) and <user>.txt
# (plain list of URIs). The .conf access keys deliberately stay outside — they
# are a single config, not a subscription.
```

- [ ] **Step 2: Write the README**

Create `ops/access-keys/README.md` in Russian, replacing what
`ops/xray-json-sub/README.md` covered. It must state:

- три файла на юзера: `<user>.conf` (Outline), `<user>.json` (Xray-подписка с
  балансером cloud1+cloud2), `<user>.txt` (все URL по строкам, первым —
  `ssconf://`);
- что генерация переехала из `outline-ss-rust`, и что URI обязаны оставаться
  побайтово теми же — это закреплено golden-корпусом в `golden/`;
- как запускать: `sudo /opt/outline/access-keys/generate_keys.py`, флаги
  `--config`, `--out-dir`, `--node`, `--dry-run`;
- что пути и `method` разрешаются **на юзера** (своё бьёт глобальное), а
  `enabled = false` исключает юзера целиком;
- таблицу ALPN по носителям и предупреждение, что `stream-one` не получает
  `http/1.1`;
- инвариант порядка outbounds в `.json` (прокси первыми, `direct`/`block`
  последними) и почему;
- что WS-ноги остаются на `http/1.1`, потому что у xray нет RFC 8441, в отличие
  от нашего сервера;
- как гонять тесты: `python3 -m unittest discover -s ops/access-keys -p "test_*.py"`;
- как пересnять golden-корпус и что делать этого можно только вместе с
  осознанным изменением формата;
- раскатку: rsync каталога на узел в `/opt/outline/access-keys/`, вызов из
  `save-keys.sh`, по одному узлу;
- слепую зону: пробы observatory не видят отказ вида «узел отвечает, а трафик
  утёк мимо туннеля».

- [ ] **Step 3: Verify no stale paths remain**

Run: `grep -rn "xray-json-sub\|generate_xray_json" ops/ docs/ --include="*.md" --include="*.sh" --include="*.conf" | grep -v "docs/superpowers"`
Expected: no output — every reference outside the historical specs and plans is gone.

- [ ] **Step 4: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/access-keys/README.md ops/access-keys/nginx-subscription-headers.conf
git commit -m "ops(access-keys): document the package and cover .txt with subscription headers"
```

---

### Task 10: Roll out to the four nodes

**Files:**
- Modify on the nodes: `/opt/outline/outline-ss-rust/save-keys.sh`
- Modify: `ops/provision-node/collect-from-reference.sh:306`

**Interfaces:**
- Consumes: the verified package from Tasks 2–9.
- Produces: three artifacts per user on every node, generated by Python.

Order: `cloud2`, `cloud1`, `nuxt`, `nuxt2` — one at a time. `cloud2` first
because round-robin DNS sends most clients to `cloud1`. No service restarts.

- [ ] **Step 1: Install the package on cloud2**

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n install -d -o root -g root -m 0755 /opt/outline/access-keys'
rsync -a --delete --exclude '__pycache__' --exclude 'test_*.py' --exclude 'golden' \
  ops/access-keys/ sysadm@cloud2.beerloga.su:/tmp/access-keys/
ssh sysadm@cloud2.beerloga.su \
  'sudo -n cp -a /tmp/access-keys/. /opt/outline/access-keys/ && rm -rf /tmp/access-keys \
   && sudo -n chown -R root:root /opt/outline/access-keys \
   && sudo -n chmod 0755 /opt/outline/access-keys/generate_keys.py && ls /opt/outline/access-keys'
```

Expected listing: `artifacts.py config_model.py generate_keys.py nginx-subscription-headers.conf outline_yaml.py README.md uri.py xray_json.py`

- [ ] **Step 2: Prove equivalence on the node's real config**

Generate both ways into scratch directories and compare the URIs. The Rust side
still works at this point, which is exactly why this check is possible.

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n bash -s' <<'EOF'
set -euo pipefail
rm -rf /tmp/keys-rust /tmp/keys-py
mkdir -p /tmp/keys-rust /tmp/keys-py
outline-ss-rust --config /opt/outline/outline-ss-rust/config.toml \
  --write-access-keys-dir /tmp/keys-rust > /dev/null
/opt/outline/access-keys/generate_keys.py \
  --config /opt/outline/outline-ss-rust/config.toml --out-dir /tmp/keys-py > /dev/null
python3 - <<'PY'
import pathlib
rust = pathlib.Path("/tmp/keys-rust")
py = pathlib.Path("/tmp/keys-py")
bad = 0
for conf in sorted(py.glob("*.conf")):
    other = rust / conf.name
    if not other.exists() or other.read_text() != conf.read_text():
        print("CONF MISMATCH", conf.name); bad += 1
for txt in sorted(py.glob("*.txt")):
    user = txt.stem
    want = {p.read_text().strip() for p in rust.glob(f"{user}-*.conf")}
    got = {line for line in txt.read_text().splitlines() if not line.startswith("ssconf://")}
    if want != got:
        print("URI MISMATCH", user, len(want), len(got)); bad += 1
print("mismatches:", bad)
PY
EOF
```

Expected: `mismatches: 0` and nothing else. **Any mismatch stops the rollout** —
fix the Python, re-run the golden suite, redeploy, and check again.

- [ ] **Step 3: Clean up the scratch directories**

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n rm -rf /tmp/keys-rust /tmp/keys-py'
```

They hold live credentials and must not linger.

- [ ] **Step 4: Switch save-keys.sh on cloud2**

Replace the file wholesale — the old one calls the binary and the Python
subscription generator separately, and both lines go away:

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n cp -a /opt/outline/outline-ss-rust/save-keys.sh \
  /opt/outline/outline-ss-rust/save-keys.sh.bak.$(date +%Y%m%d%H%M%S) \
  && sudo -n tee /opt/outline/outline-ss-rust/save-keys.sh >/dev/null <<EOF
#!/bin/sh
#
# Access-key artifacts: <user>.conf, <user>.json, <user>.txt.
# Generator lives in ops/access-keys and reads this node config.toml.
# Keys dir: /var/www/html/<keys-dir>/

/opt/outline/access-keys/generate_keys.py \
  --config /opt/outline/outline-ss-rust/config.toml \
  --out-dir /var/www/html/<keys-dir>/ \
  > /opt/outline/outline-ss-rust/users.txt
EOF
sudo -n chmod 0755 /opt/outline/outline-ss-rust/save-keys.sh && sudo -n sh -n /opt/outline/outline-ss-rust/save-keys.sh && echo "syntax ok"'
```

Expected: `syntax ok`

- [ ] **Step 5: Record the pre-switch checksums, then run it**

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n sh -c "cd /var/www/html/<keys-dir> && sha256sum *.conf | grep -vE \"-(ss|vless)-\" | sort > /tmp/conf-before.sha"'
ssh sysadm@cloud2.beerloga.su 'sudo -n /opt/outline/outline-ss-rust/save-keys.sh && echo "generated"'
ssh sysadm@cloud2.beerloga.su 'sudo -n sh -c "cd /var/www/html/<keys-dir> && sha256sum *.conf | grep -vE \"-(ss|vless)-\" | sort > /tmp/conf-after.sha; diff /tmp/conf-before.sha /tmp/conf-after.sha && echo \"outline artifacts unchanged\"; rm -f /tmp/conf-before.sha /tmp/conf-after.sha"'
```

Expected: `generated`, then `outline artifacts unchanged` — the `<user>.conf`
files must be byte-identical across the switch.

- [ ] **Step 6: Confirm the new layout**

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n sh -c "cd /var/www/html/<keys-dir> && echo -n \"conf: \"; ls *.conf | grep -cvE \"-(ss|vless)-\"; echo -n \"json: \"; ls *.json | wc -l; echo -n \"txt: \"; ls *.txt | wc -l; echo -n \"legacy: \"; ls *.conf | grep -cE \"-(ss|vless)-\" || true"'
```

Expected: 12 conf, 12 json, 12 txt, and 63 legacy files still present — they are
removed in the next step, not by the generator.

- [ ] **Step 7: Delete the legacy per-carrier files on cloud2**

The owner confirmed on 2026-08-11 that nothing subscribes to these URLs.

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n sh -c "cd /var/www/html/<keys-dir> && ls *.conf | grep -E \"-(ss|vless)-\" | xargs -r rm -- && echo -n \"remaining files: \"; ls | wc -l"'
```

Expected: `remaining files: 36` — three per user, nothing else.

- [ ] **Step 8: Verify delivery over HTTPS from cloud2**

```bash
for ext in conf json txt; do
  printf "%-5s " "$ext"
  curl -sS --max-time 20 --resolve cloud.beerloga.su:443:87.242.85.181 \
    -o /dev/null -w '%{http_code} %{content_type}\n' \
    https://cloud.beerloga.su/<keys-prefix>/beerloga.$ext
done
```

Expected: `200` for all three; `application/json` for `.json`, `text/plain` for
`.txt`.

Ask the owner to import `https://cloud.beerloga.su/<keys-prefix>/<user>.txt`
into Happ once — a plain URI list should be accepted as a subscription. This is
the one check that cannot be automated from here; if the client rejects it, the
`.txt` format needs revisiting before the remaining nodes are switched.

- [ ] **Step 9: Check the subscription headers reach `.txt`**

This requires the nginx change from Task 9 to be applied on the node. Fetch the
current site file, add the widened location, install it, `nginx -t`, reload:

```bash
ssh sysadm@cloud2.beerloga.su 'sudo -n sed -i.bak-$(date +%Y%m%d%H%M%S) \
  "s#location ~ \^/<keys-prefix>/\[^/\]+\\\\.json\\$#location ~ ^/<keys-prefix>/[^/]+\\\\.(json|txt)\$#" \
  /etc/nginx/sites-available/beerloga.su && sudo -n nginx -t 2>&1 | tail -1 && sudo -n systemctl reload nginx && echo reloaded'
curl -sS -D- --max-time 20 --resolve cloud.beerloga.su:443:87.242.85.181 -o /dev/null \
  https://cloud.beerloga.su/<keys-prefix>/beerloga.txt | grep -i "^profile-"
```

Expected: `nginx ... test is successful`, `reloaded`, then both
`profile-title` and `profile-update-interval` headers.

If the `sed` does not match (the location line differs from what Task 9 wrote),
edit the file by hand instead of forcing the expression — a half-applied regex
in an nginx config is worse than an obvious manual edit.

- [ ] **Step 10: Repeat Steps 1–9 on cloud1, then nuxt, then nuxt2**

Same commands with the node's hostname; in Step 8 and 9 use
`--resolve cloud.beerloga.su:443:176.123.167.42` for cloud1. `nuxt` and `nuxt2`
have 11 users, not 12, and serve different hostnames — adjust the expected
counts and drop the `--resolve` checks, verifying locally instead:

```bash
ssh sysadm@nuxt.beerloga.su 'curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:80/<keys-prefix>/beerloga.txt'
```

Start a node only once the previous one is fully green.

- [ ] **Step 11: Teach collect-from-reference.sh the new shape**

`ops/provision-node/collect-from-reference.sh:306` derives the keys directory by
grepping `--write-access-keys-dir` out of `save-keys.sh`. That flag is gone, so
a freshly collected bundle would carry an empty `ACCESS_KEYS_DIR`. Replace the
line:

```bash
KEYS_DIR="$(REF_SSH "sed -n 's#.*--write-access-keys-dir *##p' /opt/outline/outline-ss-rust/save-keys.sh 2>/dev/null" | tr -d ' \\' | head -1)" || KEYS_DIR=""
```

with one that accepts either shape, preferring the new one:

```bash
# save-keys.sh used to pass the directory to the binary as
# `--write-access-keys-dir`; since the generator moved to ops/access-keys it is
# `--out-dir`. Accept both so a reference node on either side still resolves.
KEYS_DIR="$(REF_SSH "sed -n 's#.*--out-dir *##p;s#.*--write-access-keys-dir *##p' /opt/outline/outline-ss-rust/save-keys.sh 2>/dev/null" | tr -d ' \\' | head -1)" || KEYS_DIR=""
```

- [ ] **Step 12: Verify the parser against a switched node**

```bash
ssh sysadm@cloud2.beerloga.su "sed -n 's#.*--out-dir *##p;s#.*--write-access-keys-dir *##p' /opt/outline/outline-ss-rust/save-keys.sh | tr -d ' \\\\' | head -1"
```

Expected: `/var/www/html/<keys-dir>/`

- [ ] **Step 13: Commit** *(only after the owner explicitly asks)*

```bash
git add ops/provision-node/collect-from-reference.sh
git commit -m "ops(provision-node): resolve the keys dir from either save-keys.sh shape"
```

---

## Notes for the implementer

- **Do not restart `outline-ss-rust`.** Only nginx gets a `reload`, and only for
  the header widening.
- **Do not print credentials.** `jq -r '.[0].outbounds[].tag'`, `sha256sum` and
  file listings are safe; `cat` of any generated artifact is not.
- **The golden corpus is the reference, never the code.** If a golden test
  fails, the Python is wrong. Regenerating `golden/expected` to make a test pass
  defeats the entire point of this plan.
- **Stop and report on any mismatch during rollout.** A node with artifacts that
  disagree with the binary is worse than a node not yet switched.
- **Stage 2 (deleting the Rust code) is a separate plan.** Do not touch
  `bins/outline-ss-rust/` in this one.