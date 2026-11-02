# Монитор дрейфа браузерных отпечатков — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** еженедельный GitHub Actions-джоб, который снимает отпечаток свежих Chrome stable и Firefox release, сравнивает его с закоммиченным эталоном браузера и держит одну issue `fingerprint-drift` в актуальном состоянии.

**Architecture:** Python-инструмент в `scripts/fingerprint-drift/`. Приёмники пишут pcap, tshark расшифровывает и собирает их, а `normalize.py` превращает их в JSON-снимок. В снимке остаются только поля, которые сравниваются точно. Шум (GREASE, случайный порядок, длины, порты, платформа, локаль) вырезается в одном месте. `compare.py` сравнивает снимок с `baseline/<browser>.json`. Эталон построен из октябрьских pcap, по которым подгоняли профили, и воспроизводится тестом. Cargo-тест связывает мажорную версию эталона с таблицей `PROFILES`.

**Tech Stack:** Python 3 только на stdlib (`unittest`, без pytest и сторонних пакетов), tshark ≥ 4.2 (поле `tls.handshake.ja4`, `-T json -x --no-duplicate-keys`), bash, openssl, Xvfb, Google Chrome stable, Firefox из apt Mozilla, GitHub Actions на `ubuntu-24.04`, Rust (`cargo test`).

Спека: [`docs/superpowers/specs/2026-11-02-fingerprint-drift-monitor-design.md`](../specs/2026-11-02-fingerprint-drift-monitor-design.md).

## Global Constraints

- Комментарии в коде, сообщения коммитов, тексты issue и отчёта — на английском. Спека, план, `README.ru.md` — на русском. Документация парная: `README.md` и `README.ru.md` меняются вместе.
- Python — только стандартная библиотека. Тесты — `unittest`. Запуск: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests`. Тесты, которым нужен tshark, помечены `needs_tshark` и без него пропускаются.
- Модули импортируют друг друга по имени (`from hello import ...`) и запускаются как скрипты из своего каталога: `python3 scripts/fingerprint-drift/normalize.py ...`. Не запускать их с `python3 -I`: изолированный режим убирает каталог скрипта из `sys.path`.
- Хост во всех сценариях — `localtest.me` (127.0.0.1). Порты: TCP h2 `8443`, TCP h1 `8444`, UDP QUIC `8445`.
- Сравнивается браузер с эталоном браузера. Наш клиент `outline-ws-rust` в джобе не собирается и не запускается.
- Сбой захвата ≠ дрейф. Код 2 из `compare.py`, падение `capture.sh` или `normalize.py` делают джоб красным, а issue не трогается.
- `scripts/quic-initial-sink.py` не переносится и не меняется: на этот путь ссылаются планы 2026-10-29.
- Коммиты делает только владелец или по его явной команде. Коммитить только свои пути: `git commit -m "..." -- <paths>`, потому что в общем индексе бывает чужое. Шаги «Commit» ниже — это готовые команды для этого момента.
- Перед каждым коммитом Rust-части прогнать CI-гейт из `AGENTS.md` (fmt по списку пакетов, clippy `--workspace --exclude sockudo-ws --all-targets --no-deps -D warnings`, `cargo test --workspace --exclude sockudo-ws`).

## Структура файлов

| Файл | Ответственность |
|---|---|
| `scripts/fingerprint-drift/hello.py` | Чистый парсер ClientHello (байты → поля), без I/O |
| `scripts/fingerprint-drift/pcapread.py` | Обёртки tshark: hello из pcap, h2-кадры, h1-запросы |
| `scripts/fingerprint-drift/normalize.py` | Правила шума и CLI «каталог захвата → снимки» |
| `scripts/fingerprint-drift/compare.py` | Дифф эталона и снимка, markdown-отчёт, код выхода |
| `scripts/fingerprint-drift/baseline/{chrome,firefox}.json` | Эталон (вывод `normalize.py` на `tests/data`) |
| `scripts/fingerprint-drift/pcapwrite.py` | Запись синтетических TCP-пакетов в pcap |
| `scripts/fingerprint-drift/tls_sink.py` | TCP-приёмник: hello + терминация TLS + ответы h2/h1 |
| `scripts/fingerprint-drift/page.html` | fetch GET/POST, WebSocket, отложенный fetch |
| `scripts/fingerprint-drift/ca.sh` | Эфемерный CA и leaf для `localtest.me`, печатает SPKI |
| `scripts/fingerprint-drift/capture.sh` | Установка браузеров, сценарии, `versions.json` |
| `scripts/fingerprint-drift/issue.sh` | Открыть, обновить или закрыть issue `fingerprint-drift` |
| `scripts/fingerprint-drift/tests/` | `common.py`, `test_*.py`, `data/` (октябрьские pcap) |
| `scripts/fingerprint-drift/README.md`, `README.ru.md` | Запуск, обновление эталона, что считается шумом |
| `.github/workflows/fingerprint-drift.yml` | Расписание, захват, сравнение, артефакт, issue |
| `crates/outline-transport/src/tests/fingerprint_profile.rs` | Тест «мажор эталона = мажор в `PROFILES`» |
| `crates/outline-transport/src/fingerprint_profile.rs` | Комментарий к `PROFILES_REFRESHED_AT_UNIX`: процедура обновления |
| `AGENTS.md` | Строка о мониторе и правило «обновил `PROFILES` → обнови эталон» |

Исходные октябрьские pcap лежат в scratchpad прошлой сессии (каталог не в репозитории, путь абсолютный):

```
OLD=/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/9485f03f-e16e-46f6-8398-2e54ca9d2af0/scratchpad
```

Проверенная копия всех файлов этого плана (прототип, прогнанный на этих pcap и в docker) лежит в `/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/795008ac-4bdd-4eb1-8e25-6e0976338572/scratchpad/fpd/tree/`. Её содержимое совпадает с блоками кода ниже.

---

### Task 1: Парсер ClientHello

**Files:**
- Create: `scripts/fingerprint-drift/tests/common.py`
- Create: `scripts/fingerprint-drift/tests/test_hello.py`
- Create: `scripts/fingerprint-drift/hello.py`

**Interfaces:**
- Produces: `hello.GREASE = "grease"`; `is_grease16(int) -> bool`; `is_grease_tp(int) -> bool`; `mask16(list[int]) -> list[int|str]`; `parse_client_hello(bytes) -> dict` с ключами `ciphers, extensions, groups, key_share, sig_algs, alpn, alps, compress_cert, supported_versions, ech, trust_anchors, transport_parameters`. `transport_parameters` — `None` или `[[id|"grease", hex|None], ...]`. На вход идёт handshake-сообщение с 4-байтовым заголовком.
- Produces: `tests/common.py` с `TESTS, TOOL, REPO, DATA, BASELINE, needs_tshark`; при импорте добавляет `TOOL` в `sys.path`.

- [ ] **Step 1: Общие пути тестов**

Create `scripts/fingerprint-drift/tests/common.py`:

```python
"""Shared paths for the tests; importing it puts the tool's modules on sys.path."""
import os
import shutil
import sys
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(TESTS)
REPO = os.path.dirname(os.path.dirname(TOOL))
DATA = os.path.join(TESTS, "data")
BASELINE = os.path.join(TOOL, "baseline")

sys.path.insert(0, TOOL)

needs_tshark = unittest.skipIf(shutil.which("tshark") is None, "tshark is not installed")
```

- [ ] **Step 2: Написать падающий тест**

Create `scripts/fingerprint-drift/tests/test_hello.py`. Фикстуры — существующие `crates/outline-transport/src/tests/fixtures/tcp_client_hello/*.bin` (handshake-сообщение с 4-байтовым заголовком):

```python
import os
import unittest

from common import REPO
from hello import GREASE, is_grease16, is_grease_tp, parse_client_hello

FIXTURES = os.path.join(REPO, "crates/outline-transport/src/tests/fixtures/tcp_client_hello")


def fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return f.read()


class GreaseTest(unittest.TestCase):
    def test_tls_grease_values(self):
        self.assertTrue(is_grease16(0x0A0A))
        self.assertTrue(is_grease16(0xFAFA))
        self.assertFalse(is_grease16(0x0A1A))
        self.assertFalse(is_grease16(0x1301))

    def test_transport_parameter_grease_ids(self):
        self.assertTrue(is_grease_tp(27))
        self.assertTrue(is_grease_tp(27 + 31 * 1000))
        self.assertFalse(is_grease_tp(0x20))
        self.assertFalse(is_grease_tp(0x11))


class ChromeHelloTest(unittest.TestCase):
    hello = parse_client_hello(fixture("chrome156_h2.bin"))

    def test_ciphers_start_with_grease(self):
        self.assertEqual(self.hello["ciphers"][:4], [GREASE, 0x1301, 0x1302, 0x1303])
        self.assertEqual(len(self.hello["ciphers"]), 16)

    def test_extensions_are_grease_bracketed(self):
        exts = self.hello["extensions"]
        self.assertEqual(exts[0], GREASE)
        self.assertEqual(exts[-1], GREASE)
        self.assertIn(51764, exts)

    def test_alpn_alps_ech(self):
        self.assertEqual(self.hello["alpn"], ["h2", "http/1.1"])
        self.assertEqual(self.hello["alps"], {"codepoint": 17613, "protocols": ["h2"]})
        self.assertTrue(self.hello["ech"])
        self.assertIsNotNone(self.hello["trust_anchors"])

    def test_groups_and_key_share(self):
        self.assertEqual(self.hello["groups"], [GREASE, 0x11EC, 0x1D, 0x17, 0x18])
        self.assertEqual(self.hello["key_share"], [GREASE, 0x11EC, 0x1D])
        self.assertEqual(self.hello["compress_cert"], [2])
        self.assertEqual(self.hello["sig_algs"][0], GREASE)
        self.assertIsNone(self.hello["transport_parameters"])


class FirefoxHelloTest(unittest.TestCase):
    hello = parse_client_hello(fixture("firefox159_h2.bin"))

    def test_fixed_extension_order_without_grease(self):
        self.assertEqual(self.hello["extensions"],
                         [0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037])

    def test_firefox_specifics(self):
        self.assertEqual(self.hello["compress_cert"], [1, 2, 3])
        self.assertEqual(self.hello["key_share"], [0x11EC, 0x1D, 0x17])
        self.assertIsNone(self.hello["alps"])
        self.assertIsNone(self.hello["trust_anchors"])


class TransportParametersTest(unittest.TestCase):
    def test_quic_transport_parameters_extension(self):
        # max_idle_timeout = 30000 (varint 0x80007530), a GREASE id 27, then
        # initial_source_connection_id with a 3-byte value.
        tp = bytes([0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 27, 0x01, 0xAA,
                    0x0F, 0x03, 0x01, 0x02, 0x03])
        ext = (57).to_bytes(2, "big") + len(tp).to_bytes(2, "big") + tp
        body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
                + len(ext).to_bytes(2, "big") + ext)
        msg = b"\x01" + len(body).to_bytes(3, "big") + body
        self.assertEqual(parse_client_hello(msg)["transport_parameters"],
                         [[1, "80007530"], [GREASE, None], [15, "010203"]])

    def test_truncated_hello_raises(self):
        with self.assertRaises(ValueError):
            parse_client_hello(fixture("chrome156_h2.bin")[:100])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_hello.py'`
Expected: `ModuleNotFoundError: No module named 'hello'`

- [ ] **Step 4: Реализация**

Create `scripts/fingerprint-drift/hello.py`:

```python
"""Parse a TLS ClientHello handshake message into comparable fields.

The input is the handshake message with its 4-byte header (type 1, 24-bit
length): what tshark's `tls.handshake_raw` holds for TCP and for QUIC CRYPTO
alike, and what `crates/outline-transport/src/tests/fixtures/tcp_client_hello/`
stores. GREASE values become the string "grease"; everything else stays an
int, a str or a hex string, so the result serialises to JSON as is.
"""

GREASE = "grease"

EXT_SUPPORTED_GROUPS = 10
EXT_SIG_ALGS = 13
EXT_ALPN = 16
EXT_COMPRESS_CERT = 27
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_QUIC_TP = 57
EXT_ALPS_OLD = 17513
EXT_ALPS = 17613
EXT_TRUST_ANCHORS = 51764
EXT_ECH = 65037


def is_grease16(value):
    """RFC 8701: 0x0a0a, 0x1a1a, ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def is_grease_tp(tp_id):
    """RFC 9000 §18.1: reserved transport parameters are 31 * N + 27."""
    return tp_id >= 27 and (tp_id - 27) % 31 == 0


def mask16(values):
    return [GREASE if is_grease16(v) else v for v in values]


class Reader:
    def __init__(self, data):
        self.data = data
        self.off = 0

    def take(self, n):
        if self.off + n > len(self.data):
            raise ValueError("truncated ClientHello")
        out = self.data[self.off:self.off + n]
        self.off += n
        return out

    def uint(self, n):
        return int.from_bytes(self.take(n), "big")

    def vec(self, len_bytes):
        return self.take(self.uint(len_bytes))

    def varint(self):
        first = self.uint(1)
        value = first & 0x3F
        for _ in range((1 << (first >> 6)) - 1):
            value = (value << 8) | self.uint(1)
        return value

    def done(self):
        return self.off >= len(self.data)


def _u16s(data, len_bytes=2):
    r = Reader(Reader(data).vec(len_bytes))
    out = []
    while not r.done():
        out.append(r.uint(2))
    return out


def _strings(data):
    r = Reader(Reader(data).vec(2))
    out = []
    while not r.done():
        out.append(r.vec(1).decode("ascii", "replace"))
    return out


def _key_share_groups(data):
    r = Reader(Reader(data).vec(2))
    out = []
    while not r.done():
        group = r.uint(2)
        r.vec(2)
        out.append(GREASE if is_grease16(group) else group)
    return out


def _compress_cert(data):
    r = Reader(Reader(data).vec(1))
    out = []
    while not r.done():
        out.append(r.uint(2))
    return out


def _transport_parameters(data):
    r = Reader(data)
    out = []
    while not r.done():
        tp_id = r.varint()
        value = r.take(r.varint())
        if is_grease_tp(tp_id):
            out.append([GREASE, None])
        else:
            out.append([tp_id, value.hex()])
    return out


def parse_client_hello(msg):
    r = Reader(msg)
    if r.uint(1) != 1:
        raise ValueError("not a ClientHello")
    body = Reader(r.take(r.uint(3)))
    body.take(2 + 32)  # legacy_version, random
    body.vec(1)  # legacy_session_id
    suites = Reader(body.vec(2))
    ciphers = []
    while not suites.done():
        ciphers.append(suites.uint(2))
    body.vec(1)  # legacy_compression_methods
    exts = Reader(body.vec(2))
    out = {
        "ciphers": mask16(ciphers),
        "extensions": [],
        "groups": [],
        "key_share": [],
        "sig_algs": [],
        "alpn": [],
        "alps": None,
        "compress_cert": [],
        "supported_versions": [],
        "ech": False,
        "trust_anchors": None,
        "transport_parameters": None,
    }
    while not exts.done():
        ext = exts.uint(2)
        data = exts.vec(2)
        out["extensions"].append(GREASE if is_grease16(ext) else ext)
        if ext == EXT_SUPPORTED_GROUPS:
            out["groups"] = mask16(_u16s(data))
        elif ext == EXT_KEY_SHARE:
            out["key_share"] = _key_share_groups(data)
        elif ext == EXT_SIG_ALGS:
            out["sig_algs"] = mask16(_u16s(data))
        elif ext == EXT_ALPN:
            out["alpn"] = _strings(data)
        elif ext in (EXT_ALPS_OLD, EXT_ALPS):
            out["alps"] = {"codepoint": ext, "protocols": _strings(data)}
        elif ext == EXT_COMPRESS_CERT:
            out["compress_cert"] = _compress_cert(data)
        elif ext == EXT_SUPPORTED_VERSIONS:
            out["supported_versions"] = mask16(_u16s(data, 1))
        elif ext == EXT_ECH:
            out["ech"] = True
        elif ext == EXT_TRUST_ANCHORS:
            out["trust_anchors"] = data.hex()
        elif ext == EXT_QUIC_TP:
            out["transport_parameters"] = _transport_parameters(data)
    return out
```

- [ ] **Step 5: Тест проходит**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_hello.py'`
Expected: `Ran 10 tests` … `OK`

- [ ] **Step 6: Commit**

```bash
git add scripts/fingerprint-drift/hello.py scripts/fingerprint-drift/tests/common.py scripts/fingerprint-drift/tests/test_hello.py
git commit -m "test(fingerprint-drift): parse TLS ClientHello fields for drift snapshots" -- scripts/fingerprint-drift/hello.py scripts/fingerprint-drift/tests/common.py scripts/fingerprint-drift/tests/test_hello.py
```

---

### Task 2: Чтение pcap через tshark и тестовые данные

**Files:**
- Create: `scripts/fingerprint-drift/tests/data/{chrome,firefox}/{h2-hello,h2-plain,h1-hello,h1-plain,quic}.pcap`, `scripts/fingerprint-drift/tests/data/versions.json`
- Create: `scripts/fingerprint-drift/tests/test_pcapread.py`
- Create: `scripts/fingerprint-drift/pcapread.py`

**Interfaces:**
- Consumes: `hello.parse_client_hello`.
- Produces: `client_hellos(pcap) -> list[{"port": int, "ja4": str, "hello": dict}]` в порядке захвата; `h2_connections(pcap) -> dict[int, list[frame]]`, где frame — `{"type", "stream", "flags"}` плюс `settings: [[id, value]]` (тип 4), `increment` (тип 8), `headers: [[name, value]]` и необязательный `priority: {"exclusive", "weight"}` (типы 1, 2); `h1_requests(pcap) -> list[{"port", "method", "path", "headers": [[name, value]]}]`, регистр имён сохраняется. Правило «decode as» выбирается по первому пакету pcap (TCP → `tls`/`http2`, UDP → `quic`).

- [ ] **Step 1: Скопировать октябрьские захваты в раскладку каталога захвата**

Соответствие выверено по датам и портам: TCP hello — стенд `tcpch` (30.10, Chrome 156 и Firefox 159), h2 и h1 открытым текстом — стенд `h2fp` (30.10), QUIC — `chello.bcEH/s*` (29.10, с SNI).

```bash
OLD=/private/tmp/claude-501/-Users-mvmalykh-IdeaProjects-outline-proxy/9485f03f-e16e-46f6-8398-2e54ca9d2af0/scratchpad
D=scripts/fingerprint-drift/tests/data
mkdir -p $D/chrome $D/firefox
cp $OLD/tcpch/chrome-page.pcap    $D/chrome/h2-hello.pcap
cp $OLD/tcpch/chrome-ws.pcap      $D/chrome/h1-hello.pcap
cp $OLD/h2fp/chrome-fetch.pcap    $D/chrome/h2-plain.pcap
cp $OLD/h2fp/chrome-h1.pcap       $D/chrome/h1-plain.pcap
cp $OLD/chello.bcEH/schrome1.pcap $D/chrome/quic.pcap
cp $OLD/tcpch/ff-page.pcap        $D/firefox/h2-hello.pcap
cp $OLD/tcpch/ff-ws.pcap          $D/firefox/h1-hello.pcap
cp $OLD/h2fp/ff-fetch.pcap        $D/firefox/h2-plain.pcap
cp $OLD/h2fp/ff-h1.pcap           $D/firefox/h1-plain.pcap
cp $OLD/chello.bcEH/sff1.pcap     $D/firefox/quic.pcap
printf '{"chrome": "Google Chrome 156.0.0.0", "firefox": "Mozilla Firefox 159.0"}\n' > $D/versions.json
du -sh $D
```

Expected: `156K` или около того. Все захваты сделаны на localhost: секретов в них нет, сертификаты стендов были самоподписанными.

- [ ] **Step 2: Написать падающий тест**

Create `scripts/fingerprint-drift/tests/test_pcapread.py`:

```python
import os
import unittest

from common import DATA, needs_tshark
from pcapread import client_hellos, h1_requests, h2_connections


def pcap(browser, name):
    return os.path.join(DATA, browser, name)


@needs_tshark
class ClientHellosTest(unittest.TestCase):
    def test_tcp_hellos_carry_ja4_and_fields(self):
        hellos = client_hellos(pcap("chrome", "h2-hello.pcap"))
        self.assertGreater(len(hellos), 1)
        self.assertTrue(hellos[0]["ja4"].startswith("t13d1517h2_8daaf6152771_"))
        self.assertEqual(hellos[0]["hello"]["alpn"], ["h2", "http/1.1"])

    def test_quic_hello_is_decrypted_with_transport_parameters(self):
        (first, *_) = client_hellos(pcap("firefox", "quic.pcap"))
        self.assertEqual(first["ja4"], "q13d0315h3_55b375c5d22e_dc5437974b47")
        ids = [tp[0] for tp in first["hello"]["transport_parameters"]]
        self.assertEqual(ids[:3], [1, 4, 5])

    def test_chrome_websocket_hello_offers_http11_only(self):
        alpns = [h["hello"]["alpn"] for h in client_hellos(pcap("chrome", "h1-hello.pcap"))]
        self.assertIn(["http/1.1"], alpns)


@needs_tshark
class PlaintextTest(unittest.TestCase):
    def test_h2_frames_per_connection(self):
        conns = h2_connections(pcap("chrome", "h2-plain.pcap"))
        frames = next(iter(conns.values()))
        self.assertEqual(frames[0]["type"], 4)
        self.assertEqual(frames[0]["settings"][0], [1, 65536])
        headers = [fr for fr in frames if fr["type"] == 1]
        self.assertEqual(headers[0]["headers"][0], [":method", "GET"])
        self.assertEqual(headers[0]["priority"], {"exclusive": 1, "weight": 255})

    def test_h1_requests_keep_header_case_and_skip_bodies(self):
        reqs = h1_requests(pcap("chrome", "h1-plain.pcap"))
        kinds = {(r["method"], r["path"]) for r in reqs}
        self.assertTrue({("GET", "/page"), ("POST", "/post-xhr"), ("GET", "/ws")} <= kinds)
        page = next(r for r in reqs if r["path"] == "/page")
        self.assertEqual(page["headers"][0][0], "Host")
        self.assertIn(["sec-ch-ua-mobile", "?0"], page["headers"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Убедиться, что тест падает**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_pcapread.py'`
Expected: `ModuleNotFoundError: No module named 'pcapread'`

- [ ] **Step 4: Реализация**

Create `scripts/fingerprint-drift/pcapread.py`. Две ловушки tshark, учтённые в коде: без `--no-duplicate-keys` JSON теряет повторяющиеся поля. ClientHello, разбитый на несколько QUIC-пакетов, приходит списком фрагментов, и полное сообщение выбирается по его 24-битной длине (на `schrome2.pcap` первый фрагмент обрезан).

```python
"""Read the capture pcaps through tshark.

tshark decrypts QUIC Initials, reassembles CRYPTO and TCP, computes JA4 and
decodes HPACK; everything after that is plain Python. Each pcap holds one
server port (the sinks write synthetic packets to it), which selects the
"decode as" rule.
"""
import json
import subprocess

from hello import parse_client_hello


def _tshark(args):
    return subprocess.run(["tshark", *args], capture_output=True, text=True, check=True).stdout


def _decode_as(pcap, tcp_proto, udp_proto):
    first = _tshark(["-r", pcap, "-c", "1", "-T", "fields", "-e", "tcp.dstport", "-e", "udp.dstport"])
    tcp, _, udp = first.strip("\n").partition("\t")
    if tcp:
        return f"tcp.port=={tcp},{tcp_proto}"
    if udp:
        return f"udp.port=={udp},{udp_proto}"
    raise ValueError(f"{pcap}: no TCP or UDP packet")


def _packets(pcap, decode, display, raw=False):
    args = ["-r", pcap, "-d", decode, "-Y", display, "-T", "json", "--no-duplicate-keys"]
    if raw:
        args.append("-x")
    out = _tshark(args)
    return [p["_source"]["layers"] for p in json.loads(out)] if out.strip() else []


def _find(obj, key):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from _find(v, key)
    elif isinstance(obj, list):
        for x in obj:
            yield from _find(x, key)


def _hex_strings(raw):
    """tshark `_raw` is [hex, offset, length, bitmask, type] or a list of those."""
    if isinstance(raw, list) and raw and isinstance(raw[0], str):
        yield raw[0]
    elif isinstance(raw, list):
        for x in raw:
            yield from _hex_strings(x)


def _complete_hello(raws):
    # A ClientHello split over several QUIC packets shows up as one fragment
    # per packet plus the reassembled message: take the one whose 24-bit
    # length covers it exactly.
    for raw in raws:
        for h in _hex_strings(raw):
            b = bytes.fromhex(h)
            if len(b) >= 4 and b[0] == 1 and len(b) == 4 + int.from_bytes(b[1:4], "big"):
                return b
    raise ValueError("no complete ClientHello in packet")


def _first(layers, *keys):
    for key in keys:
        for v in _find(layers, key):
            return v
    return None


def client_hellos(pcap):
    """Every ClientHello in capture order: {"port", "ja4", "hello"}."""
    decode = _decode_as(pcap, "tls", "quic")
    out = []
    for layers in _packets(pcap, decode, "tls.handshake.type==1", raw=True):
        out.append({
            "port": int(_first(layers, "tcp.srcport", "udp.srcport")),
            "ja4": _first(layers, "tls.handshake.ja4"),
            "hello": parse_client_hello(_complete_hello(_find(layers, "tls.handshake_raw"))),
        })
    return out


def _aslist(v):
    return v if isinstance(v, list) else [v]


def _frame(st):
    fr = {"type": int(st["http2.type"]), "stream": int(st["http2.streamid"]),
          "flags": int(st.get("http2.flags", "0x00"), 16)}
    if fr["type"] == 4:
        fr["settings"] = []
        for s in _aslist(st.get("http2.settings", [])):
            value = next(v for k, v in s.items()
                         if k.startswith("http2.settings.") and k != "http2.settings.id")
            fr["settings"].append([int(s["http2.settings.id"]), int(value)])
    elif fr["type"] == 8:
        fr["increment"] = int(st["http2.window_update.window_size_increment"])
    elif fr["type"] in (1, 2):
        if "http2.headers.weight" in st:
            fr["priority"] = {"exclusive": int(st["http2.exclusive"]),
                              "weight": int(st["http2.headers.weight"])}
        fr["headers"] = [[h["http2.header.name"], h.get("http2.header.value", "")]
                         for h in _aslist(st.get("http2.header", []))]
    return fr


def h2_connections(pcap):
    """Frames of every h2 connection, keyed by client port, in order."""
    decode = _decode_as(pcap, "http2", "http2")
    conns = {}
    for layers in _packets(pcap, decode, "http2"):
        port = int(_first(layers, "tcp.srcport"))
        for h2 in _aslist(layers.get("http2", [])):
            for st in _aslist(h2.get("http2.stream", [])):
                if "http2.type" in st:
                    conns.setdefault(port, []).append(_frame(st))
    return conns


def _streams(pcap):
    """Client bytes of every TCP connection, keyed by client port."""
    out = _tshark(["-r", pcap, "-T", "fields", "-e", "tcp.srcport", "-e", "tcp.seq_raw",
                   "-e", "tcp.payload"])
    parts = {}
    for line in out.splitlines():
        port, seq, payload = line.split("\t")
        if payload:
            parts.setdefault(int(port), []).append((int(seq), bytes.fromhex(payload)))
    return {port: b"".join(p for _, p in sorted(chunks)) for port, chunks in parts.items()}


def h1_requests(pcap):
    """Every HTTP/1.1 request head: {"port", "method", "path", "headers"}.

    Header names keep their case: the case is part of the fingerprint.
    """
    out = []
    for port, data in sorted(_streams(pcap).items()):
        while data:
            head, sep, rest = data.partition(b"\r\n\r\n")
            if not sep:
                break
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = [list(map(str.strip, ln.split(":", 1))) for ln in lines[1:]]
            out.append({"port": port, "method": method, "path": path, "headers": headers})
            length = next((int(v) for n, v in headers if n.lower() == "content-length"), 0)
            data = rest[length:]
    return out
```

- [ ] **Step 5: Тест проходит**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_pcapread.py'`
Expected: `Ran 5 tests` … `OK`

- [ ] **Step 6: Commit**

```bash
git add scripts/fingerprint-drift/pcapread.py scripts/fingerprint-drift/tests/test_pcapread.py scripts/fingerprint-drift/tests/data
git commit -m "test(fingerprint-drift): read hellos and h2/h1 requests from pcaps via tshark" -- scripts/fingerprint-drift/pcapread.py scripts/fingerprint-drift/tests/test_pcapread.py scripts/fingerprint-drift/tests/data
```

---

### Task 3: Нормализация и эталон

**Files:**
- Create: `scripts/fingerprint-drift/tests/test_normalize.py`
- Create: `scripts/fingerprint-drift/normalize.py`
- Create: `scripts/fingerprint-drift/baseline/chrome.json`, `scripts/fingerprint-drift/baseline/firefox.json` (генерируются, руками не пишутся)

**Interfaces:**
- Consumes: `pcapread.client_hellos`, `h2_connections`, `h1_requests`; `hello.GREASE`.
- Produces: `normalize.snapshot(capture_dir, browser, version_line) -> dict` с ключами `browser, major, tcp_h2, tcp_h1, quic, h2, h1`. `h2` = `{settings, window_update, stream_window_update, priority: {kind: …}, headers: {kind: [[n, v]]}}`, `h1` = `{kind: [[n, v]]}`, kind ∈ `navigate, fetch_get, fetch_post, ws`. Ещё `major(str) -> int`, `normalize_headers(list) -> list`, `write_json(path, obj)` (indent 2, sort_keys, перевод строки в конце). CLI: `normalize.py <capture-dir> <snapshot-dir>`.

Правила шума (проверены на трёх захватах каждого браузера):

| Поле | Правило | Почему |
|---|---|---|
| порядок расширений | множество, кроме Firefox TCP | Chrome перемешивает всегда, Firefox — только в QUIC (`sff1..3`) |
| порядок QUIC TP | множество, кроме Firefox | у Chrome случайный (`schrome1..3`), у Firefox фиксированный |
| TP `0x0f` (SCID) | только длина `len:N` | у Firefox случайные 3 байта |
| TP `0x11` (version_information) | GREASE-версии `0x?a?a?a?a` → `grease`; у Chrome остальные версии после выбранной — множество | случайные; Chrome ещё и ставит GREASE на случайное место среди версий (найдено прогоном 2026-11-02) |
| JA4 | только части a и b (`ja4_ab`) | c-часть у Chrome хеширует GREASE в sig_algs и меняется от hello к hello; поля, из которых она считается, сравниваются явно |
| длины hello, ECH, padding | не сохраняются | зависят от SNI и случайны |
| `host`, `:authority`, `origin`, `referer`, `sec-websocket-key`, `accept-language` | значение → `<volatile>`, имя и позиция остаются | порт, ключ и локаль машины |
| `user-agent` | первые скобки → `(<platform>)`, `HeadlessChrome/` → `Chrome/` | эталон снят на macOS (часть Chrome headless), CI работает на Linux |
| `sec-ch-ua-platform` | → `<platform>` | то же |

- [ ] **Step 1: Написать падающий тест**

Create `scripts/fingerprint-drift/tests/test_normalize.py`:

```python
import json
import os
import unittest

from common import BASELINE, DATA, needs_tshark
from hello import GREASE
from normalize import (_as_set, _transport_parameters, _version_information, major,
                       normalize_headers, normalize_hello, snapshot)


class RulesTest(unittest.TestCase):
    def test_major(self):
        self.assertEqual(major("Google Chrome 157.0.7900.12"), 157)
        self.assertEqual(major("Mozilla Firefox 160.0.1"), 160)
        with self.assertRaises(ValueError):
            major("Firefox")

    def test_set_keeps_grease_count(self):
        self.assertEqual(_as_set([GREASE, 16, 0, GREASE, 5]), [0, 5, 16, GREASE, GREASE])

    def test_version_information_firefox_keeps_order(self):
        self.assertEqual(_version_information("firefox", "00000001ea9aaa3a6b3343cf"),
                         ["00000001", GREASE, "6b3343cf"])

    def test_version_information_chrome_ignores_reserved_position(self):
        expected = ["00000001", "00000001", GREASE]
        self.assertEqual(_version_information("chrome", "00000001ea9aaa3a00000001"), expected)
        self.assertEqual(_version_information("chrome", "0000000100000001ea9aaa3a"), expected)

    def test_transport_parameters_firefox_keep_order(self):
        tps = [[15, "acaa3d"], [1, "80007530"], [GREASE, None]]
        self.assertEqual(_transport_parameters("firefox", tps),
                         [[15, "len:3"], [1, "80007530"], [GREASE, None]])

    def test_transport_parameters_chrome_sorted(self):
        tps = [[GREASE, None], [9, "4064"], [1, "80007530"], [15, ""]]
        self.assertEqual(_transport_parameters("chrome", tps),
                         [[1, "80007530"], [9, "4064"], [15, "len:0"], [GREASE, None]])

    def test_extension_order_compared_only_for_firefox_tcp(self):
        record = {"ja4": "t13d1517h2_8daaf6152771_63ff51340b64",
                  "hello": {"extensions": [16, GREASE, 0], "transport_parameters": None}}
        self.assertEqual(normalize_hello("chrome", "tcp", record)["extensions"], [0, 16, GREASE])
        self.assertEqual(normalize_hello("firefox", "tcp", record)["extensions"], [16, GREASE, 0])
        self.assertEqual(normalize_hello("firefox", "quic", record)["extensions"],
                         [0, 16, GREASE])
        self.assertEqual(normalize_hello("chrome", "tcp", record)["ja4_ab"],
                         "t13d1517h2_8daaf6152771")

    def test_headers_drop_platform_and_volatile_values(self):
        headers = [
            [":authority", "localtest.me:8443"],
            ["user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                           "HeadlessChrome/157.0.0.0 Safari/537.36"],
            ["sec-ch-ua-platform", "\"Linux\""],
            ["Accept-Language", "ru-RU,ru;q=0.9"],
            ["accept", "*/*"],
        ]
        self.assertEqual(normalize_headers(headers), [
            [":authority", "<volatile>"],
            ["user-agent", "Mozilla/5.0 (<platform>) AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/157.0.0.0 Safari/537.36"],
            ["sec-ch-ua-platform", "<platform>"],
            ["Accept-Language", "<volatile>"],
            ["accept", "*/*"],
        ])


@needs_tshark
class BaselineTest(unittest.TestCase):
    """The committed baselines are exactly what normalize.py makes of the
    2026-10-29…31 captures in tests/data."""

    def check(self, browser):
        with open(os.path.join(DATA, "versions.json")) as f:
            version_line = json.load(f)[browser]
        with open(os.path.join(BASELINE, f"{browser}.json")) as f:
            baseline = json.load(f)
        # Round-trip through JSON: tuples and lists compare alike there.
        got = json.loads(json.dumps(snapshot(DATA, browser, version_line)))
        self.assertEqual(got, baseline)

    def test_chrome(self):
        self.check("chrome")

    def test_firefox(self):
        self.check("firefox")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_normalize.py'`
Expected: `ModuleNotFoundError: No module named 'normalize'`

- [ ] **Step 3: Реализация**

Create `scripts/fingerprint-drift/normalize.py`:

```python
#!/usr/bin/env python3
"""Turn one capture directory into one comparable snapshot per browser.

Usage: normalize.py <capture-dir> <snapshot-dir>

<capture-dir> holds `versions.json` and one subdirectory per browser with
`h2-hello.pcap`, `h2-plain.pcap`, `h1-hello.pcap`, `h1-plain.pcap` and
`quic.pcap` (see capture.sh). Each `<snapshot-dir>/<browser>.json` is what
compare.py diffs against `baseline/<browser>.json`.

This file is the one place that decides what counts as noise. Everything it
keeps is compared exactly.
"""
import json
import os
import re
import sys

from hello import GREASE
from pcapread import client_hellos, h1_requests, h2_connections

# Where a browser sends a fixed order: compared as captured. Everywhere else
# the order is random per hello and the field is compared as a sorted set.
ORDERED = {
    ("firefox", "tcp_extensions"),
    ("firefox", "quic_transport_parameters"),
}

TP_INITIAL_SOURCE_CID = 0x0F
TP_VERSION_INFORMATION = 0x11

# Values that change per run, per port or per machine locale; the header
# itself (name and position) is still compared.
VOLATILE_HEADERS = {"host", ":authority", "origin", "referer", "sec-websocket-key",
                    "accept-language"}

REQUEST_KINDS = [
    ("navigate", lambda m, p: m == "GET" and p == "/page"),
    ("fetch_get", lambda m, p: m == "GET" and p == "/get-xhr"),
    ("fetch_post", lambda m, p: m == "POST" and p == "/post-xhr"),
    ("ws", lambda m, p: p == "/ws"),
]


def major(version_line):
    m = re.search(r"(\d+)\.", version_line)
    if not m:
        raise ValueError(f"no version in {version_line!r}")
    return int(m.group(1))


def _as_set(values):
    """Sorted ints, then one "grease" per GREASE value."""
    ints = sorted(v for v in values if v != GREASE)
    return ints + [GREASE] * (len(values) - len(ints))


def _version_information(browser, hex_value):
    data = bytes.fromhex(hex_value)
    versions = [data[i:i + 4].hex() for i in range(0, len(data), 4)]
    # Reserved versions (RFC 9000 §15) follow 0x?a?a?a?a and are random.
    versions = [GREASE if all(int(v[i], 16) == 0xA for i in (1, 3, 5, 7)) else v
                for v in versions]
    if (browser, "quic_transport_parameters") in ORDERED:
        return versions
    # Chrome places its reserved version at a random spot among the other
    # versions, while the chosen version (first) keeps its place.
    return versions[:1] + _as_set(versions[1:])


def _transport_parameters(browser, tps):
    out = []
    for tp_id, value in tps:
        if tp_id == GREASE:
            out.append([GREASE, None])
        elif tp_id == TP_INITIAL_SOURCE_CID:
            out.append([tp_id, f"len:{len(value) // 2}"])
        elif tp_id == TP_VERSION_INFORMATION:
            out.append([tp_id, _version_information(browser, value)])
        else:
            out.append([tp_id, value])
    if (browser, "quic_transport_parameters") in ORDERED:
        return out
    return sorted((tp for tp in out if tp[0] != GREASE), key=lambda tp: tp[0]) + \
        [tp for tp in out if tp[0] == GREASE]


def normalize_hello(browser, transport, record):
    h = dict(record["hello"])
    h["ja4_ab"] = record["ja4"].rsplit("_", 1)[0]
    if (browser, f"{transport}_extensions") not in ORDERED:
        h["extensions"] = _as_set(h["extensions"])
    if h["transport_parameters"] is not None:
        h["transport_parameters"] = _transport_parameters(browser, h["transport_parameters"])
    return h


def _platform_free(name, value):
    lower = name.lower()
    if lower in VOLATILE_HEADERS:
        return "<volatile>"
    if lower == "user-agent":
        value = value.replace("HeadlessChrome/", "Chrome/")
        return re.sub(r"\([^)]*\)", "(<platform>)", value, count=1)
    if lower == "sec-ch-ua-platform":
        return "<platform>"
    return value


def normalize_headers(headers):
    return [[name, _platform_free(name, value)] for name, value in headers]


def _kind(method, path):
    return next((kind for kind, match in REQUEST_KINDS if match(method, path)), None)


def _first_hello(records, prefer=None):
    if prefer:
        for r in records:
            if prefer(r["hello"]):
                return r
    if not records:
        raise ValueError("no ClientHello captured")
    return records[0]


def normalize_h2(conns):
    """SETTINGS, windows and per-request headers of the navigation connection."""
    def requests(frames):
        for fr in frames:
            if fr["type"] == 1:
                h = dict(fr["headers"])
                yield fr, _kind(h.get(":method"), h.get(":path"))

    nav = next((frames for frames in conns.values()
                if any(kind == "navigate" for _, kind in requests(frames))), None)
    if nav is None:
        raise ValueError("no h2 navigation request captured")
    settings = next(fr["settings"] for fr in nav if fr["type"] == 4 and not fr["flags"] & 1)
    window = next((fr["increment"] for fr in nav if fr["type"] == 8 and fr["stream"] == 0), None)
    stream_window = next((fr["increment"] for fr in nav if fr["type"] == 8 and fr["stream"]), None)
    out = {"settings": settings, "window_update": window, "stream_window_update": stream_window,
           "priority": {}, "headers": {}}
    for frames in [nav] + [f for f in conns.values() if f is not nav]:
        for fr, kind in requests(frames):
            if kind and kind not in out["headers"]:
                out["headers"][kind] = normalize_headers(fr["headers"])
                out["priority"][kind] = fr.get("priority")
    return out


def normalize_h1(requests):
    out = {}
    for req in requests:
        kind = _kind(req["method"], req["path"])
        if kind and kind not in out:
            out[kind] = normalize_headers(req["headers"])
    return out


def snapshot(capture_dir, browser, version_line):
    d = os.path.join(capture_dir, browser)
    return {
        "browser": browser,
        "major": major(version_line),
        "tcp_h2": normalize_hello(browser, "tcp", _first_hello(
            client_hellos(os.path.join(d, "h2-hello.pcap")))),
        # Chrome opens its WebSocket connection with `http/1.1` alone; Firefox
        # reuses its page hello, so the first hello stands in.
        "tcp_h1": normalize_hello(browser, "tcp", _first_hello(
            client_hellos(os.path.join(d, "h1-hello.pcap")),
            prefer=lambda h: "h2" not in h["alpn"])),
        "quic": normalize_hello(browser, "quic", _first_hello(
            client_hellos(os.path.join(d, "quic.pcap")))),
        "h2": normalize_h2(h2_connections(os.path.join(d, "h2-plain.pcap"))),
        "h1": normalize_h1(h1_requests(os.path.join(d, "h1-plain.pcap"))),
    }


def write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def main(argv):
    capture_dir, snapshot_dir = argv[1], argv[2]
    with open(os.path.join(capture_dir, "versions.json")) as f:
        versions = json.load(f)
    os.makedirs(snapshot_dir, exist_ok=True)
    for browser, version_line in sorted(versions.items()):
        write_json(os.path.join(snapshot_dir, f"{browser}.json"),
                   snapshot(capture_dir, browser, version_line))


if __name__ == "__main__":
    main(sys.argv)
```

- [ ] **Step 4: Сгенерировать эталон**

```bash
python3 scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/data scripts/fingerprint-drift/baseline
python3 -c 'import json; [print(b, s["major"], s["tcp_h2"]["ja4_ab"], s["tcp_h1"]["ja4_ab"], s["quic"]["ja4_ab"], s["h2"]["settings"]) for b in ("chrome","firefox") for s in [json.load(open(f"scripts/fingerprint-drift/baseline/{b}.json"))]]'
```

Expected (сверено с памятью замеров 29–31.10):

```
chrome 156 t13d1517h2_8daaf6152771 t13d1516h1_8daaf6152771 q13d0312h3_55b375c5d22e [[1, 65536], [2, 0], [4, 6291456], [6, 262144]]
firefox 159 t13d1517h2_8daaf6152771 t13d1517h2_8daaf6152771 q13d0315h3_55b375c5d22e [[1, 65536], [2, 0], [4, 131072], [5, 16384]]
```

Просмотреть оба JSON глазами: в `h2.headers.navigate` у Chrome есть `sec-ch-ua` с `v="156"`, у Firefox UA заканчивается на `Firefox/159.0`, нигде нет портов `85xx`/`84xx` и `ru-RU`.

- [ ] **Step 5: Тест проходит**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_normalize.py'`
Expected: `Ran 10 tests` … `OK` (вместе с `BaselineTest`: эталон воспроизводится из `tests/data`)

- [ ] **Step 6: Commit**

```bash
git add scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/test_normalize.py scripts/fingerprint-drift/baseline
git commit -m "feat(fingerprint-drift): normalize captures into snapshots; baseline Chrome 156 / Firefox 159" -- scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/test_normalize.py scripts/fingerprint-drift/baseline
```

---

### Task 4: Сравнение и отчёт

**Files:**
- Create: `scripts/fingerprint-drift/tests/test_compare.py`
- Create: `scripts/fingerprint-drift/compare.py`

**Interfaces:**
- Consumes: снимки формата Task 3.
- Produces: `MATCH=0, DRIFT=1, INCOMPLETE=2`; `diff(old, new) -> [(path, old, new)]` (словари рекурсивно, списки — листья); `report_browser(name, baseline, snapshot|None) -> (code, lines)`; `main(argv) -> int`. CLI: `compare.py <baseline-dir> <snapshot-dir> <report.md>`, код выхода — худший по браузерам. Отчёт на английском, заголовки `## <browser>: drift` / `## <browser>: matches the baseline (<major>)`, строка `**<browser> <old> → <new>**` при смене мажора.

- [ ] **Step 1: Написать падающий тест**

Create `scripts/fingerprint-drift/tests/test_compare.py`:

```python
import copy
import json
import os
import tempfile
import unittest

from common import BASELINE
from compare import DRIFT, INCOMPLETE, MATCH, diff, main, report_browser


def load(browser):
    with open(os.path.join(BASELINE, f"{browser}.json")) as f:
        return json.load(f)


class DiffTest(unittest.TestCase):
    def test_nested_paths(self):
        self.assertEqual(diff({"a": {"b": 1, "c": [1]}}, {"a": {"b": 2, "c": [1]}}),
                         [("a.b", 1, 2)])
        self.assertEqual(diff({"a": 1}, {"a": 1, "b": 2}), [("b", None, 2)])


class ReportTest(unittest.TestCase):
    def test_identical_snapshot_matches(self):
        code, _ = report_browser("chrome", load("chrome"), load("chrome"))
        self.assertEqual(code, MATCH)

    def test_changed_field_is_drift(self):
        snap = load("chrome")
        snap["quic"]["sig_algs"] = snap["quic"]["sig_algs"] + [2055]
        code, lines = report_browser("chrome", load("chrome"), snap)
        self.assertEqual(code, DRIFT)
        self.assertTrue(any(ln.startswith("- `quic.sig_algs`") for ln in lines), lines)

    def test_new_major_gets_its_own_line(self):
        snap = load("firefox")
        snap["major"] += 1
        code, lines = report_browser("firefox", load("firefox"), snap)
        self.assertEqual(code, DRIFT)
        self.assertTrue(any("firefox 159 → 160" in ln for ln in lines), lines)

    def test_header_change_is_a_line_diff(self):
        snap = load("chrome")
        snap["h1"]["ws"] = snap["h1"]["ws"] + [["Priority", "u=0"]]
        _, lines = report_browser("chrome", load("chrome"), snap)
        self.assertIn("+Priority: u=0", lines)

    def test_missing_layer_is_incomplete(self):
        snap = copy.deepcopy(load("chrome"))
        snap["quic"] = None
        code, _ = report_browser("chrome", load("chrome"), snap)
        self.assertEqual(code, INCOMPLETE)

    def test_missing_snapshot_is_incomplete(self):
        code, _ = report_browser("chrome", load("chrome"), None)
        self.assertEqual(code, INCOMPLETE)


class MainTest(unittest.TestCase):
    def test_worst_code_wins_and_report_is_written(self):
        with tempfile.TemporaryDirectory() as snaps:
            snap = load("chrome")
            snap["major"] += 1
            with open(os.path.join(snaps, "chrome.json"), "w") as f:
                json.dump(snap, f)
            report = os.path.join(snaps, "report.md")
            # firefox.json is missing: INCOMPLETE beats chrome's DRIFT.
            self.assertEqual(main(["compare.py", BASELINE, snaps, report]), INCOMPLETE)
            with open(report) as f:
                self.assertIn("## chrome: drift", f.read())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Убедиться, что тест падает**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_compare.py'`
Expected: `ModuleNotFoundError: No module named 'compare'`

- [ ] **Step 3: Реализация**

Create `scripts/fingerprint-drift/compare.py`:

````python
#!/usr/bin/env python3
"""Diff the browser snapshots against the baselines.

Usage: compare.py <baseline-dir> <snapshot-dir> <report.md>

Every `<baseline-dir>/<browser>.json` is compared with the snapshot of the
same name. The report is Markdown. Exit code: 0 — every snapshot matches,
1 — drift, 2 — a snapshot is missing or lacks a layer the baseline has (a
capture failure, not drift; it wins over 1).
"""
import difflib
import json
import os
import sys

MATCH, DRIFT, INCOMPLETE = 0, 1, 2

LAYERS = ("tcp_h2", "tcp_h1", "quic", "h2", "h1")


def _fmt(value):
    return json.dumps(value, sort_keys=True)


def _is_header_list(value):
    return isinstance(value, list) and value and all(
        isinstance(x, list) and len(x) == 2 and isinstance(x[0], str) for x in value)


def diff(old, new, path=""):
    """[(path, old, new)] for every leaf that differs; lists are leaves."""
    if isinstance(old, dict) and isinstance(new, dict):
        out = []
        for key in sorted(set(old) | set(new)):
            out += diff(old.get(key), new.get(key), f"{path}.{key}" if path else key)
        return out
    return [] if old == new else [(path, old, new)]


def incomplete_layers(baseline, snapshot):
    return [layer for layer in LAYERS
            if baseline.get(layer) and not snapshot.get(layer)]


def report_browser(name, baseline, snapshot):
    """(code, markdown lines) for one browser."""
    if snapshot is None:
        return INCOMPLETE, [f"## {name}", "", "Snapshot missing: the capture failed.", ""]
    missing = incomplete_layers(baseline, snapshot)
    if missing:
        return INCOMPLETE, [f"## {name}", "", f"Snapshot lacks layers: {', '.join(missing)}.", ""]
    changes = diff(baseline, snapshot)
    if not changes:
        return MATCH, [f"## {name}: matches the baseline ({baseline['major']})", ""]
    lines = [f"## {name}: drift", ""]
    if baseline["major"] != snapshot["major"]:
        lines += [f"**{name} {baseline['major']} → {snapshot['major']}**: update the UA and "
                  "`sec-ch-ua` in `crates/outline-transport/src/fingerprint_profile.rs`, "
                  "then `scripts/fingerprint-drift/baseline/*.json`.", ""]
    for path, old, new in changes:
        if path == "major":
            continue
        if _is_header_list(old) and _is_header_list(new):
            lines += [f"- `{path}`:", "", "```diff"]
            lines += [ln for ln in difflib.unified_diff(
                [f"{n}: {v}" for n, v in old], [f"{n}: {v}" for n, v in new],
                "baseline", "snapshot", lineterm="", n=1)]
            lines += ["```"]
        else:
            lines += [f"- `{path}`: `{_fmt(old)}` → `{_fmt(new)}`"]
    return DRIFT, lines + [""]


def _load(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def main(argv):
    baseline_dir, snapshot_dir, report_path = argv[1], argv[2], argv[3]
    code, lines = MATCH, ["# Browser fingerprint drift", ""]
    for file in sorted(os.listdir(baseline_dir)):
        if not file.endswith(".json"):
            continue
        name = file[:-len(".json")]
        c, ls = report_browser(name, _load(os.path.join(baseline_dir, file)),
                               _load(os.path.join(snapshot_dir, file)))
        code = max(code, c)
        lines += ls
    with open(report_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
````

- [ ] **Step 4: Тест проходит**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_compare.py'`
Expected: `Ran 8 tests` … `OK`

- [ ] **Step 5: Commit**

```bash
git add scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/tests/test_compare.py
git commit -m "feat(fingerprint-drift): diff snapshots against the baseline into a Markdown report" -- scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/tests/test_compare.py
```

---

### Task 5: Cargo-тест «мажор эталона = мажор в `PROFILES`»

**Files:**
- Modify: `crates/outline-transport/src/tests/fingerprint_profile.rs` (новый тест после `profile_pool_must_be_refreshed_at_least_every_refresh_period`)
- Modify: `crates/outline-transport/src/fingerprint_profile.rs:208-217` (комментарий к `PROFILES_REFRESHED_AT_UNIX`)

**Interfaces:**
- Consumes: `baseline/{chrome,firefox}.json` (ключ верхнего уровня `"major": N`, как его пишет `write_json`); `PROFILES`, `Profile` (уже импортированы в файле тестов).

- [ ] **Step 1: Написать тест**

В `crates/outline-transport/src/tests/fingerprint_profile.rs` сразу после теста `profile_pool_must_be_refreshed_at_least_every_refresh_period` добавить:

```rust
/// `"major": N` at the top of a drift baseline (`normalize.py` writes it with
/// `indent=2, sort_keys=True`; no other key of the snapshot is named `major`).
fn drift_baseline_major(json: &str) -> u32 {
    let rest = json
        .split("\"major\": ")
        .nth(1)
        .expect("drift baseline has a \"major\" key");
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("drift baseline major is a number")
}

#[test]
fn drift_baselines_describe_the_profiled_browser_majors() {
    // scripts/fingerprint-drift/baseline/*.json are the browser snapshots the
    // weekly drift monitor compares fresh browsers with. They must describe the
    // releases PROFILES imitates: refreshing one without the other makes the
    // monitor report drift against the wrong reference (or stay silent on it).
    let baselines: [(&str, &str, &str); 2] = [
        (
            include_str!("../../../../scripts/fingerprint-drift/baseline/chrome.json"),
            "chrome-",
            "Chrome/",
        ),
        (
            include_str!("../../../../scripts/fingerprint-drift/baseline/firefox.json"),
            "firefox-",
            "Firefox/",
        ),
    ];
    for (json, name_prefix, ua_token) in baselines {
        let major = drift_baseline_major(json);
        let profiles: Vec<&Profile> = PROFILES
            .iter()
            .filter(|p| p.name.starts_with(name_prefix))
            .collect();
        assert!(!profiles.is_empty(), "no {name_prefix}* profile in PROFILES");
        for p in profiles {
            assert!(
                p.user_agent.contains(&format!("{ua_token}{major}.")),
                "{}: user_agent {:?} does not match drift baseline major {major}; \
                 update both (see scripts/fingerprint-drift/README.md)",
                p.name,
                p.user_agent,
            );
            if let Some(sec_ch_ua) = p.sec_ch_ua {
                assert!(
                    sec_ch_ua.contains(&format!("\"Chromium\";v=\"{major}\"")),
                    "{}: sec_ch_ua {sec_ch_ua:?} does not match drift baseline major {major}",
                    p.name,
                );
            }
        }
    }
}
```

- [ ] **Step 2: Тест проходит на текущих таблицах**

Run: `cargo test -p outline-transport drift_baselines_describe_the_profiled_browser_majors`
Expected: `test ...drift_baselines_describe_the_profiled_browser_majors ... ok`

- [ ] **Step 3: Тест ловит рассинхрон**

Временно поменять в `scripts/fingerprint-drift/baseline/firefox.json` `"major": 159` на `160`, затем:
Run: `cargo test -p outline-transport drift_baselines_describe_the_profiled_browser_majors`
Expected: FAIL `firefox-159-macos: user_agent ... does not match drift baseline major 160`.
Вернуть `159` (`git checkout -- scripts/fingerprint-drift/baseline/firefox.json`, если эталон уже закоммичен, иначе руками) и перепроверить, что тест снова `ok`.

- [ ] **Step 4: Процедура обновления в комментарии**

В `crates/outline-transport/src/fingerprint_profile.rs` заменить строки

```rust
/// re-detecting this binary). To refresh: update each `user_agent`
/// and `sec_ch_ua` field in the table below, bump the constant to
/// the current `date +%s`, then re-run the suite.
```

на

```rust
/// re-detecting this binary). To refresh: update each `user_agent`
/// and `sec_ch_ua` field in the table below, bump the constant to
/// the current `date +%s`, re-measure the browser hellos and rebuild
/// `scripts/fingerprint-drift/baseline/*.json` from the new captures
/// (`scripts/fingerprint-drift/README.md`; a test ties the baseline
/// majors to this table), then re-run the suite.
```

- [ ] **Step 5: CI-гейт**

Run (из `AGENTS.md`):

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test -p outline-transport
```

Expected: всё зелёное. Полный `cargo test --workspace --exclude sockudo-ws` — перед коммитом.

- [ ] **Step 6: Commit**

```bash
git add crates/outline-transport/src/tests/fingerprint_profile.rs crates/outline-transport/src/fingerprint_profile.rs
git commit -m "test(transport): tie fingerprint drift baseline majors to PROFILES" -- crates/outline-transport/src/tests/fingerprint_profile.rs crates/outline-transport/src/fingerprint_profile.rs
```

---

### Task 6: Приёмник TLS и стенд

**Files:**
- Create: `scripts/fingerprint-drift/pcapwrite.py`
- Create: `scripts/fingerprint-drift/page.html`
- Create: `scripts/fingerprint-drift/ca.sh` (исполняемый)
- Create: `scripts/fingerprint-drift/tests/test_tls_sink.py`
- Create: `scripts/fingerprint-drift/tls_sink.py`

**Interfaces:**
- Consumes: `pcapread.client_hellos`, `h1_requests` (в тесте).
- Produces: `PcapWriter(path, server_port).write_stream(client_port, data)` и `.close()`; `tls_sink.serve(port, cert, key, out_prefix, seconds, h1_only=False, alt_svc=None) -> {"hellos": int, "connections": int}`, пишет `<out_prefix>-hello.pcap` и `<out_prefix>-plain.pcap`; константа `tls_sink.H2_PREFACE`. CLI: `tls_sink.py <port> <cert.pem> <key.pem> <out-prefix> <seconds> [--h1-only] [--alt-svc PORT]`, код выхода 1, если не было ни одного hello. `ca.sh <dir>` создаёт `ca.pem ca.key leaf.pem leaf.key chain.pem` и печатает base64 SHA-256 SPKI leaf'а.

Две ловушки, которые учтены в коде:
- **CA должен иметь `keyUsage`.** Python ≥ 3.13 (и NSS) отвергают CA без него: `CA cert does not include key usage extension`.
- **Браузеры кодируют `:path` по Хаффману.** Приёмник не декодирует HPACK, поэтому по h2 отвечает 200 с `page.html` на любой запрос. Рендерит страницу только навигация, а у fetch и WebSocket тело игнорируется.
- **Без session tickets.** Октябрьский приёмник не завершал рукопожатие, поэтому эталонные hello — без возобновления. Если приёмник выдаёт билеты, второе соединение (WebSocket Chrome по h1) возобновляется и добавляет `pre_shared_key` (41): JA4 `t13d1517h1` вместо `t13d1516h1`. Это ложный дрейф, найденный прогоном в docker. Отсюда `ctx.num_tickets = 0` и тест `test_second_connection_is_not_resumed`.

- [ ] **Step 1: Запись pcap**

Create `scripts/fingerprint-drift/pcapwrite.py`:

```python
"""Write synthetic IPv4/TCP packets into a LINKTYPE_RAW pcap.

The sinks know the bytes a client sent, not the packets it sent them in; a
synthetic segment per chunk is enough for tshark's TLS / HTTP dissectors
(`-d tcp.port==<port>,tls|http2`). Thread-safe: one sink thread per
connection appends to the same file.
"""
import socket
import struct
import threading
import time

LINKTYPE_RAW = 101
CHUNK = 16000


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


class PcapWriter:
    def __init__(self, path, server_port):
        self.server_port = server_port
        self.lock = threading.Lock()
        self.file = open(path, "wb")
        self.file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        self.file.flush()

    def write_stream(self, client_port, data):
        """`data` as consecutive segments from 127.0.0.1:<client_port>."""
        with self.lock:
            seq = 1
            for i in range(0, max(len(data), 1), CHUNK):
                chunk = data[i:i + CHUNK]
                tcp = struct.pack("!HHIIBBHHH", client_port, self.server_port, seq, 1,
                                  0x50, 0x18, 65535, 0, 0) + chunk
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                                 socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
                ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
                packet = ip + tcp
                now = time.time()
                self.file.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6),
                                            len(packet), len(packet)) + packet)
                seq += len(chunk)
            self.file.flush()

    def close(self):
        with self.lock:
            self.file.close()
```

- [ ] **Step 2: Страница и CA**

Create `scripts/fingerprint-drift/page.html`:

```html
<!doctype html>
<html><body><script>
fetch("/get-xhr");
fetch("/post-xhr", {method: "POST", body: "abcd"});
new WebSocket("wss://" + location.host + "/ws");
setTimeout(() => fetch("/again"), 1500);
</script></body></html>
```

Create `scripts/fingerprint-drift/ca.sh` и `chmod +x scripts/fingerprint-drift/ca.sh`:

```bash
#!/usr/bin/env bash
# Make a throwaway CA and a leaf for localtest.me in <dir>; print the leaf's
# SPKI SHA-256 (base64), which Chrome takes in --ignore-certificate-errors-spki-list.
set -euo pipefail
dir=$1
mkdir -p "$dir"
cd "$dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=fingerprint-drift CA" -keyout ca.key -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=localtest.me" -keyout leaf.key -out leaf.csr 2>/dev/null
printf 'subjectAltName=DNS:localtest.me\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile leaf.ext -out leaf.pem 2>/dev/null
cat leaf.pem ca.pem > chain.pem
openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
```

- [ ] **Step 3: Написать падающий тест**

Create `scripts/fingerprint-drift/tests/test_tls_sink.py`. Тест проверяет TLS по-настоящему: тестовый CA и имя `localtest.me`, а не отключённую проверку.

```python
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from common import TOOL, needs_tshark
from pcapread import client_hellos, h1_requests
import tls_sink


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@needs_tshark
class TlsSinkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        ca = os.path.join(cls.tmp.name, "ca")
        subprocess.run([os.path.join(TOOL, "ca.sh"), ca], check=True, capture_output=True)
        cls.cert, cls.key = os.path.join(ca, "chain.pem"), os.path.join(ca, "leaf.key")
        cls.ca_pem = os.path.join(ca, "ca.pem")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def start(self, prefix, **kwargs):
        port = free_port()
        result = {}
        t = threading.Thread(target=lambda: result.update(tls_sink.serve(
            port, self.cert, self.key, prefix, 2.0, **kwargs)))
        t.start()
        time.sleep(0.3)
        return port, t, result

    def connect(self, port, alpn):
        """TLS to 127.0.0.1:<port>, verified against the test CA as localtest.me."""
        ctx = ssl.create_default_context(cafile=self.ca_pem)
        ctx.set_alpn_protocols(alpn)
        raw = socket.create_connection(("127.0.0.1", port))
        return ctx.wrap_socket(raw, server_hostname="localtest.me")

    def test_h1_page_hello_and_request_are_recorded(self):
        prefix = os.path.join(self.tmp.name, "h1")
        port, t, result = self.start(prefix, h1_only=True, alt_svc=9999)
        with self.connect(port, ["http/1.1"]) as conn:
            conn.sendall(b"GET /page HTTP/1.1\r\nHost: localtest.me\r\n\r\n")
            resp = b""
            while b"</html>" not in resp:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                resp += chunk
        t.join()
        self.assertTrue(resp.startswith(b"HTTP/1.1 200 OK\r\n"), resp[:40])
        self.assertIn(b'alt-svc: h3=":9999"\r\n', resp)
        self.assertIn(b"new WebSocket", resp)
        self.assertEqual(result["hellos"], 1)
        hellos = client_hellos(f"{prefix}-hello.pcap")
        self.assertEqual(hellos[0]["hello"]["alpn"], ["http/1.1"])
        reqs = h1_requests(f"{prefix}-plain.pcap")
        self.assertEqual([(r["method"], r["path"]) for r in reqs], [("GET", "/page")])

    def test_second_connection_is_not_resumed(self):
        prefix = os.path.join(self.tmp.name, "resume")
        port, t, _ = self.start(prefix, h1_only=True)
        ctx = ssl.create_default_context(cafile=self.ca_pem)
        sessions = []
        for _ in range(2):
            raw = socket.create_connection(("127.0.0.1", port))
            with ctx.wrap_socket(raw, server_hostname="localtest.me",
                                 session=sessions[-1] if sessions else None) as conn:
                conn.sendall(b"GET /x HTTP/1.1\r\nHost: localtest.me\r\n\r\n")
                conn.recv(4096)  # TLS 1.3 tickets would arrive with the response
                sessions.append(conn.session)
                reused = conn.session_reused
        t.join()
        self.assertFalse(reused)
        hellos = client_hellos(f"{prefix}-hello.pcap")
        self.assertNotIn(41, hellos[1]["hello"]["extensions"])

    def test_h2_server_offers_extended_connect(self):
        prefix = os.path.join(self.tmp.name, "h2")
        port, t, _ = self.start(prefix)
        with self.connect(port, ["h2"]) as conn:
            self.assertEqual(conn.selected_alpn_protocol(), "h2")
            conn.sendall(tls_sink.H2_PREFACE + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            data = b""
            while len(data) < 15:
                data += conn.recv(1024)
        t.join()
        # SETTINGS frame with ENABLE_CONNECT_PROTOCOL (8) = 1.
        self.assertEqual(data[3], 4)
        self.assertEqual(data[9:15], b"\x00\x08\x00\x00\x00\x01")
        self.assertEqual(client_hellos(f"{prefix}-hello.pcap")[0]["hello"]["alpn"], ["h2"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Убедиться, что тест падает**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -p 'test_tls_sink.py'`
Expected: `ModuleNotFoundError: No module named 'tls_sink'`

- [ ] **Step 5: Реализация**

Create `scripts/fingerprint-drift/tls_sink.py`:

```python
#!/usr/bin/env python3
"""TLS sink: record each client's ClientHello and its decrypted requests.

Usage: tls_sink.py <port> <cert.pem> <key.pem> <out-prefix> <seconds> [--h1-only] [--alt-svc PORT]

Per TCP connection on 127.0.0.1:<port>:
1. peeks the TLS records up to the end of the ClientHello and appends them to
   `<out-prefix>-hello.pcap` (decode with `-d tcp.port==<port>,tls`);
2. terminates TLS (ALPN `h2,http/1.1`, or `http/1.1` with --h1-only) and
   answers like a minimal web server so the page's requests all go out:
   over h1 `page.html` on `/page`, an empty 200 otherwise and 101 to a
   WebSocket upgrade; over h2 a 200 with `page.html` to every request;
3. on close or after HOLD seconds appends everything the client sent after
   the handshake to `<out-prefix>-plain.pcap` (decode as http2 or http).

--alt-svc PORT adds `alt-svc: h3=":PORT"` to every response, so Firefox
tries HTTP/3 and its QUIC Initial reaches quic-initial-sink.py.
"""
import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import threading
import time

from pcapwrite import PcapWriter

HOLD = 4.0
PAGE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "page.html"), "rb").read()
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 lets browsers open WebSocket over h2.
H2_SERVER_SETTINGS = b"\x00\x00\x06\x04\x00\x00\x00\x00\x00" + struct.pack("!HI", 8, 1)
H2_SETTINGS_ACK = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"


def hello_records(raw):
    """Peek until the ClientHello handshake message is complete; return its records."""
    deadline = time.time() + 5
    while time.time() < deadline:
        data = raw.recv(65536, socket.MSG_PEEK)
        off, hs = 0, b""
        while off + 5 <= len(data):
            length = int.from_bytes(data[off + 3:off + 5], "big")
            if off + 5 + length > len(data):
                break
            hs += data[off + 5:off + 5 + length]
            off += 5 + length
            if len(hs) >= 4 and len(hs) >= 4 + int.from_bytes(hs[1:4], "big"):
                return data[:off]
        if not data:
            return None
        time.sleep(0.02)
    return None


def hpack_literal(name, value):
    """Literal header field without indexing, new name, no Huffman."""
    name, value = name.encode(), value.encode()
    return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value


def h2_frame(frame_type, flags, stream, payload):
    return len(payload).to_bytes(3, "big") + bytes([frame_type, flags]) + \
        stream.to_bytes(4, "big") + payload


class Connection:
    def __init__(self, conn, alpn, alt_svc):
        self.conn, self.alpn, self.alt_svc = conn, alpn, alt_svc
        self.received = b""
        self.answered = 0  # bytes of `received` already handled

    def extra_headers(self):
        return [("alt-svc", f'h3=":{self.alt_svc}"')] if self.alt_svc else []

    def handle_h2(self):
        if not self.answered:
            if len(self.received) < len(H2_PREFACE):
                return
            self.conn.sendall(H2_SERVER_SETTINGS + H2_SETTINGS_ACK)
            self.answered = len(H2_PREFACE)
        while len(self.received) >= self.answered + 9:
            off = self.answered
            length = int.from_bytes(self.received[off:off + 3], "big")
            if len(self.received) < off + 9 + length:
                return
            frame_type = self.received[off + 3]
            stream = int.from_bytes(self.received[off + 5:off + 9], "big") & 0x7FFFFFFF
            self.answered = off + 9 + length
            if frame_type == 1:
                # Browsers Huffman-code :path, so the sink does not route:
                # every request (the CONNECT of a WebSocket too) gets 200 and
                # the page, which only the navigation renders.
                block = b"\x88" + hpack_literal("content-type", "text/html")  # :status 200
                for name, value in self.extra_headers():
                    block += hpack_literal(name, value)
                self.conn.sendall(h2_frame(1, 0x04, stream, block) +
                                  h2_frame(0, 0x01, stream, PAGE))

    def handle_h1(self):
        while True:
            head, sep, _ = self.received[self.answered:].partition(b"\r\n\r\n")
            if not sep:
                return
            lines = head.decode("latin-1").split("\r\n")
            headers = {k.strip().lower(): v.strip() for k, v in
                       (ln.split(":", 1) for ln in lines[1:] if ":" in ln)}
            length = int(headers.get("content-length", "0"))
            end = self.answered + len(head) + 4 + length
            if len(self.received) < end:
                return
            self.answered = end
            extra = "".join(f"{n}: {v}\r\n" for n, v in self.extra_headers())
            if headers.get("upgrade", "").lower() == "websocket":
                accept = base64.b64encode(hashlib.sha1(
                    headers.get("sec-websocket-key", "").encode() + WS_GUID).digest()).decode()
                self.conn.sendall((f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                   f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n"
                                   f"{extra}\r\n").encode())
                return
            body = PAGE if lines[0].split(" ")[1] == "/page" else b""
            self.conn.sendall((f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                               f"Content-Length: {len(body)}\r\n{extra}\r\n").encode() + body)

    def run(self):
        self.conn.settimeout(0.2)
        deadline = time.time() + HOLD
        while time.time() < deadline:
            try:
                data = self.conn.recv(65536)
            except socket.timeout:
                continue
            except (OSError, ssl.SSLError):
                break
            if not data:
                break
            self.received += data
            try:
                self.handle_h2() if self.alpn == "h2" else self.handle_h1()
            except (OSError, ssl.SSLError):
                break
        return self.received


def serve(port, cert, key, out_prefix, seconds, h1_only=False, alt_svc=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["http/1.1"] if h1_only else ["h2", "http/1.1"])
    # No session tickets: a browser would resume on its second connection and
    # add pre_shared_key (41) to that hello. The baselines are fresh hellos.
    ctx.num_tickets = 0
    hellos = PcapWriter(f"{out_prefix}-hello.pcap", port)
    plain = PcapWriter(f"{out_prefix}-plain.pcap", port)
    counts = {"hellos": 0, "connections": 0}

    def handle(raw, addr):
        try:
            raw.settimeout(5)
            records = hello_records(raw)
            if records is None:
                return
            hellos.write_stream(addr[1], records)
            counts["hellos"] += 1
            conn = ctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError) as e:
            print(f"tls_sink {port}: {addr[1]}: {e}", file=sys.stderr, flush=True)
            raw.close()
            return
        received = Connection(conn, conn.selected_alpn_protocol(), alt_svc).run()
        try:
            conn.close()
        except OSError:
            pass
        plain.write_stream(addr[1], received)
        counts["connections"] += 1

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    srv.settimeout(0.5)
    threads = []
    end = time.time() + seconds
    while time.time() < end:
        try:
            raw, addr = srv.accept()
        except socket.timeout:
            continue
        t = threading.Thread(target=handle, args=(raw, addr), daemon=True)
        t.start()
        threads.append(t)
    srv.close()
    for t in threads:
        t.join(HOLD + 6)
    hellos.close()
    plain.close()
    print(f"tls_sink {port}: {counts['hellos']} hellos, {counts['connections']} connections",
          file=sys.stderr, flush=True)
    return counts


def main(argv):
    args = argv[1:]
    h1_only = "--h1-only" in args
    alt_svc = None
    if "--alt-svc" in args:
        alt_svc = int(args[args.index("--alt-svc") + 1])
    port, cert, key, out_prefix, seconds = args[:5]
    counts = serve(int(port), cert, key, out_prefix, float(seconds), h1_only, alt_svc)
    return 0 if counts["hellos"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 6: Тест проходит, весь набор тоже**

Run: `python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests`
Expected: `Ran 36 tests` … `OK`

- [ ] **Step 7: Commit**

```bash
git add scripts/fingerprint-drift/pcapwrite.py scripts/fingerprint-drift/page.html scripts/fingerprint-drift/ca.sh scripts/fingerprint-drift/tls_sink.py scripts/fingerprint-drift/tests/test_tls_sink.py
git commit -m "feat(fingerprint-drift): TLS sink recording hellos and decrypted h2/h1 requests" -- scripts/fingerprint-drift/pcapwrite.py scripts/fingerprint-drift/page.html scripts/fingerprint-drift/ca.sh scripts/fingerprint-drift/tls_sink.py scripts/fingerprint-drift/tests/test_tls_sink.py
```

---

### Task 7: Захват свежих браузеров

**Files:**
- Create: `scripts/fingerprint-drift/capture.sh` (исполняемый)

**Interfaces:**
- Consumes: `ca.sh`, `tls_sink.py`, `scripts/quic-initial-sink.py <port> <out.pcap> <seconds>`.
- Produces: каталог захвата: `versions.json` (`{"chrome": "Google Chrome N…", "firefox": "Mozilla Firefox N…"}`) и `<browser>/{h2,h1}-{hello,plain}.pcap`, `<browser>/quic.pcap`, `<browser>/*.log`, `ca/`. Ровно эту раскладку читает `normalize.py`.

Что выяснил прогон 2026-11-02 и что учтено в скрипте:
- Сейчас Chrome stable 156.0.8078.79 и Firefox 159.0, те же мажоры, что в эталоне. Первый прогон в CI, скорее всего, покажет совпадение или мелкие отличия, а не смену мажора.
- Firefox идёт на QUIC в том же прогоне, что и страница по h2: приёмник шлёт `alt-svc: h3=":8445"`, Firefox отправляет Initial на UDP 8445. Отдельный сценарий не нужен.
- Chrome под root (docker) требует `--no-sandbox`; на раннере пользователь не root, флаг не ставится. Других флагов, кроме необходимых для сертификата и QUIC, нет: каждый лишний флаг рискует поменять отпечаток.
- `localtest.me` пинится в `/etc/hosts`, а у Firefox выключен DoH (`network.trr.mode=5`): сбой резолвера не должен выглядеть как изменение браузера.
- `CHROME=`/`FIREFOX=` переопределяют бинари для локального прогона без `--install`.

- [ ] **Step 1: Скрипт захвата**

Create `scripts/fingerprint-drift/capture.sh` и `chmod +x scripts/fingerprint-drift/capture.sh`:

```bash
#!/usr/bin/env bash
# Capture what fresh Chrome stable and Firefox release send to local sinks.
#
# Usage: capture.sh [--install] <out-dir>
#
# --install  apt-installs tshark, Xvfb, NSS tools, Google Chrome stable (Google's
#            repository) and Firefox release (Mozilla's repository, not snap/ESR).
#
# CHROME / FIREFOX override the browser binaries (default google-chrome,
# firefox), e.g. CHROME=chromium for a local arm64 run without --install.
#
# Writes <out-dir>/versions.json and, per browser, <out-dir>/<browser>/
# {h2,h1}-{hello,plain}.pcap and quic.pcap — the layout normalize.py reads.
# Linux only. Exits non-zero when a sink saw no ClientHello: a capture failure,
# never reported as drift.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
install=0
if [ "${1:-}" = --install ]; then install=1; shift; fi
[ $# -eq 1 ] || { echo "usage: $0 [--install] <out-dir>" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)
sudo=; [ "$(id -u)" = 0 ] || sudo=sudo

TCP_H2=8443
TCP_H1=8444
UDP_QUIC=8445
SINK_SECS=16
BROWSER_SECS=12
CHROME=${CHROME:-google-chrome}
FIREFOX=${FIREFOX:-firefox}

install_deps() {
  export DEBIAN_FRONTEND=noninteractive
  $sudo apt-get update -qq
  $sudo apt-get install -y -qq ca-certificates wget gnupg tshark xvfb xauth libnss3-tools \
    openssl python3 >/dev/null
  wget -qO- https://dl.google.com/linux/linux_signing_key.pub \
    | $sudo gpg --dearmor --yes -o /usr/share/keyrings/google-chrome.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
    | $sudo tee /etc/apt/sources.list.d/google-chrome.list >/dev/null
  $sudo install -d -m 0755 /etc/apt/keyrings
  wget -qO- https://packages.mozilla.org/apt/repo-signing-key.gpg \
    | $sudo tee /etc/apt/keyrings/packages.mozilla.org.asc >/dev/null
  echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" \
    | $sudo tee /etc/apt/sources.list.d/mozilla.list >/dev/null
  printf 'Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n' \
    | $sudo tee /etc/apt/preferences.d/mozilla >/dev/null
  $sudo apt-get update -qq
  $sudo apt-get install -y -qq google-chrome-stable firefox >/dev/null
}

[ $install = 1 ] && install_deps
# localtest.me resolves to 127.0.0.1 publicly; pin it so a resolver hiccup is
# not mistaken for a browser change.
grep -q 'localtest\.me' /etc/hosts || echo '127.0.0.1 localtest.me' | $sudo tee -a /etc/hosts >/dev/null

spki=$("$here/ca.sh" "$out/ca")
cert=$out/ca/chain.pem
key=$out/ca/leaf.key

printf '{"chrome": "%s", "firefox": "%s"}\n' "$($CHROME --version)" "$($FIREFOX --version)" \
  > "$out/versions.json"
cat "$out/versions.json"

pids=()
tls_sink() { # <port> <out-prefix> [sink flags...]
  python3 "$here/tls_sink.py" "$1" "$cert" "$key" "$2" "$SINK_SECS" "${@:3}" &
  pids+=($!)
}
quic_sink() { # <port> <out.pcap>
  python3 "$repo/scripts/quic-initial-sink.py" "$1" "$2" "$SINK_SECS" &
  pids+=($!)
}
wait_sinks() {
  local failed=0
  for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
  pids=()
  return $failed
}

chrome() { # <log> <args...>
  local log=$1; shift
  local sandbox=(); [ "$(id -u)" = 0 ] && sandbox=(--no-sandbox)
  timeout "$BROWSER_SECS" xvfb-run -a "$CHROME" "${sandbox[@]}" \
    --user-data-dir="$(mktemp -d)" --no-first-run --no-default-browser-check \
    --ignore-certificate-errors-spki-list="$spki" "$@" >"$log" 2>&1 || true
}

firefox_profile() {
  local p
  p=$(mktemp -d)
  certutil -N -d "sql:$p" --empty-password
  certutil -A -n fingerprint-drift -t "C,," -i "$out/ca/ca.pem" -d "sql:$p"
  cat > "$p/user.js" <<'EOF'
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("network.trr.mode", 5);
EOF
  echo "$p"
}

firefox_run() { # <log> <url>
  timeout "$BROWSER_SECS" xvfb-run -a "$FIREFOX" --no-remote --profile "$(firefox_profile)" "$2" \
    >"$1" 2>&1 || true
}

mkdir -p "$out/chrome" "$out/firefox"

# Chrome: page over h2 (hello, preface, navigation, fetch, WebSocket over h2) ...
tls_sink $TCP_H2 "$out/chrome/h2"
chrome "$out/chrome/h2.log" "https://localtest.me:$TCP_H2/page"
wait_sinks
# ... over http/1.1 only (the WebSocket connection's own `http/1.1` hello) ...
tls_sink $TCP_H1 "$out/chrome/h1" --h1-only
chrome "$out/chrome/h1.log" "https://localtest.me:$TCP_H1/page"
wait_sinks
# ... and the QUIC Initial, forced: no TCP leg at all.
quic_sink $UDP_QUIC "$out/chrome/quic.pcap"
chrome "$out/chrome/quic.log" --origin-to-force-quic-on="localtest.me:$UDP_QUIC" \
  "https://localtest.me:$UDP_QUIC/page"
wait_sinks

# Firefox: the h2 page advertises Alt-Svc, so the same run sends the QUIC Initial.
tls_sink $TCP_H2 "$out/firefox/h2" --alt-svc $UDP_QUIC
quic_sink $UDP_QUIC "$out/firefox/quic.pcap"
firefox_run "$out/firefox/h2.log" "https://localtest.me:$TCP_H2/page"
wait_sinks
tls_sink $TCP_H1 "$out/firefox/h1" --h1-only
firefox_run "$out/firefox/h1.log" "https://localtest.me:$TCP_H1/page"
wait_sinks

echo "capture: $out"
```

- [ ] **Step 2: Проверка в docker на маке (amd64, как раннер)**

У Google Chrome нет сборки linux/arm64, поэтому нужен `--platform linux/amd64`. Docker Desktop эмулирует его через Rosetta, установка занимает несколько минут.

```bash
OUT=$(mktemp -d)
docker run --rm --platform linux/amd64 -v "$PWD":/src -v "$OUT":/work -w /src ubuntu:24.04 bash -c '
  apt-get update -qq && apt-get install -y -qq wget gnupg ca-certificates >/dev/null &&
  scripts/fingerprint-drift/capture.sh --install /work/cap &&
  python3 scripts/fingerprint-drift/normalize.py /work/cap /work/snap &&
  python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline /work/snap /work/report.md;
  echo compare=$?'
cat "$OUT/report.md"
```

Expected: в начале `versions.json` с текущими версиями. Каждый приёмник печатает `N hellos` с N ≥ 1. `normalize.py` проходит без исключений, `compare=` равен `0` или `1`, но не `2`. В отчёте нет расхождений, объяснимых окружением (порт, локаль, платформа, `Headless`, возобновление сессии). Если они есть, правило шума в `normalize.py` неполно: дополнить его, прогнать Task 3 и только потом идти дальше.

Если docker на маке эмулирует amd64 через QEMU (в логе `qemu: uncaught target signal`), Chrome падает в GPU- и рендер-процессе и успевает отправить только навигацию. Это ограничение эмуляции, а не скрипта. Тогда механику проверить на arm64 с Chromium и Firefox ESR (шаг 3), а полную проверку на amd64 оставить ручному `workflow_dispatch` (Task 10).

- [ ] **Step 3: Проверка механики на arm64 (Chromium, Firefox ESR)**

```bash
OUT=$(mktemp -d)
printf 'FROM debian:trixie\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chromium firefox-esr xvfb xauth libnss3-tools tshark openssl python3 >/dev/null\n' \
  | docker build -q -t fpdrift-arm:local -
docker run --rm -e CHROME=chromium -e FIREFOX=firefox-esr -v "$PWD":/src -v "$OUT":/work -w /src fpdrift-arm:local bash -c '
  scripts/fingerprint-drift/capture.sh /work/cap && python3 scripts/fingerprint-drift/normalize.py /work/cap /work/snap'
python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline "$OUT/snap" "$OUT/report.md"
grep -E '^## |^- ' "$OUT/report.md"
```

Expected (проверено 2026-11-02 на Chromium 156.0.8078.73): у Chrome различаются только заголовки с `sec-ch-ua` (у Chromium нет бренда `"Google Chrome"`): `h1.fetch_get`, `h1.fetch_post`, `h1.navigate`, `h2.headers.fetch_get`, `h2.headers.fetch_post`, `h2.headers.navigate`. Hello по TCP h2/h1 и QUIC, SETTINGS, приоритеты и оба WebSocket совпадают. У Firefox ESR дрейф ожидаем: это другая ветка. Главное, что `snap/firefox.json` содержит все слои, включая `quic`, пришедший через Alt-Svc.

- [ ] **Step 4: Commit**

```bash
git add scripts/fingerprint-drift/capture.sh
git commit -m "feat(fingerprint-drift): capture fresh Chrome and Firefox against local sinks" -- scripts/fingerprint-drift/capture.sh
```

---

### Task 8: Workflow и issue

**Files:**
- Create: `scripts/fingerprint-drift/issue.sh` (исполняемый)
- Create: `.github/workflows/fingerprint-drift.yml`

**Interfaces:**
- Consumes: `capture.sh --install`, `normalize.py`, `compare.py` (коды 0/1/2), `issue.sh <code> <report.md> <run-url>` (нужен `GH_TOKEN`).

- [ ] **Step 1: Скрипт issue**

Create `scripts/fingerprint-drift/issue.sh` и `chmod +x scripts/fingerprint-drift/issue.sh`:

```bash
#!/usr/bin/env bash
# Keep the one open `fingerprint-drift` issue in step with the latest run.
#
# Usage: issue.sh <compare-exit-code> <report.md> <run-url>
#
# Exit code 1 (drift) opens the issue or replaces its body with the new report;
# 0 (match) closes an open one. 2 never reaches here: the workflow fails first.
# Needs GH_TOKEN with issues: write; gh takes the repository from the checkout.
set -euo pipefail
code=$1
report=$2
run_url=$3
label=fingerprint-drift

gh label create "$label" --color D93F0B \
  --description "Fresh browsers no longer match scripts/fingerprint-drift/baseline" 2>/dev/null || true
number=$(gh issue list --label "$label" --state open --json number --jq '.[0].number // empty')
body="$(cat "$report")

Run: $run_url"

if [ "$code" = 1 ]; then
  if [ -n "$number" ]; then
    gh issue edit "$number" --body "$body"
  else
    gh issue create --title "Browser fingerprint drift" --label "$label" --body "$body"
  fi
elif [ -n "$number" ]; then
  gh issue close "$number" --comment "Fresh browsers match the baseline again: $run_url"
fi
```

Run: `bash -n scripts/fingerprint-drift/issue.sh && shellcheck scripts/fingerprint-drift/*.sh`
Expected: без вывода.

- [ ] **Step 2: Workflow**

Create `.github/workflows/fingerprint-drift.yml`. Pinned SHA взяты из `ci.yml`:

```yaml
name: fingerprint drift

# Weekly check that the browsers our client imitates still look the way the
# profiles were tuned to: fresh Chrome stable and Firefox release are captured
# against local sinks (scripts/fingerprint-drift/capture.sh), normalized and
# diffed against scripts/fingerprint-drift/baseline/*.json. Drift keeps one
# open `fingerprint-drift` issue up to date; a failed capture fails the job
# and leaves the issue alone. Pull requests touching the tool run everything
# except the issue step.
on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:
  pull_request:
    paths:
      - "scripts/fingerprint-drift/**"
      - "scripts/quic-initial-sink.py"
      - ".github/workflows/fingerprint-drift.yml"

permissions:
  contents: read
  issues: write

concurrency:
  group: fingerprint-drift-${{ github.ref }}
  cancel-in-progress: true

jobs:
  drift:
    name: capture and compare
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: install tshark
        run: |
          sudo apt-get update -qq
          sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark

      - name: unit tests
        run: python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests -v

      - name: capture fresh browsers
        run: scripts/fingerprint-drift/capture.sh --install "$RUNNER_TEMP/capture"

      - name: normalize
        run: python3 scripts/fingerprint-drift/normalize.py "$RUNNER_TEMP/capture" "$RUNNER_TEMP/snapshot"

      - name: compare with the baseline
        id: compare
        run: |
          set +e
          python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline \
            "$RUNNER_TEMP/snapshot" "$RUNNER_TEMP/report.md"
          code=$?
          set -e
          cat "$RUNNER_TEMP/report.md" >> "$GITHUB_STEP_SUMMARY"
          echo "code=$code" >> "$GITHUB_OUTPUT"
          # 2 = a snapshot lacks a layer: a capture failure, not drift.
          [ "$code" -le 1 ]

      - name: upload capture
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: fingerprint-drift
          path: |
            ${{ runner.temp }}/capture
            ${{ runner.temp }}/snapshot
            ${{ runner.temp }}/report.md
          if-no-files-found: ignore
          retention-days: 30

      - name: update the drift issue
        if: github.event_name != 'pull_request' && steps.compare.outcome == 'success'
        env:
          GH_TOKEN: ${{ github.token }}
          CODE: ${{ steps.compare.outputs.code }}
          RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
        run: scripts/fingerprint-drift/issue.sh "$CODE" "$RUNNER_TEMP/report.md" "$RUN_URL"
```

- [ ] **Step 3: Проверка синтаксиса**

Run: `actionlint .github/workflows/fingerprint-drift.yml`
Expected: без вывода, код 0. В `run:` не подставляются выражения из событий (`${{ github.event.* }}`): ссылка на прогон и код идут через `env:`, issue-шаг на pull request не запускается.

- [ ] **Step 4: Commit**

```bash
git add scripts/fingerprint-drift/issue.sh .github/workflows/fingerprint-drift.yml
git commit -m "ci: weekly browser fingerprint drift monitor with a tracking issue" -- scripts/fingerprint-drift/issue.sh .github/workflows/fingerprint-drift.yml
```

---

### Task 9: Документация

**Files:**
- Create: `scripts/fingerprint-drift/README.md`
- Create: `scripts/fingerprint-drift/README.ru.md`
- Modify: `AGENTS.md` (раздел «CI-гейт — гнать локально перед коммитом», после абзаца про третий job)
- Modify: `docs/superpowers/specs/2026-11-02-fingerprint-drift-monitor-design.md` (pytest → unittest; отчёт и issue на английском)

- [ ] **Step 1: README (EN)**

Create `scripts/fingerprint-drift/README.md`:

````markdown
# Browser fingerprint drift monitor

🌐 [Русский](README.ru.md)

`outline-ws-rust` imitates browsers on every layer a DPI box can see: the TCP
and QUIC ClientHello, QUIC transport parameters, the HTTP/2 preface and the
request headers. The profiles (`crates/outline-transport/src/fingerprint_profile.rs`
and the tables next to it) were tuned against Chrome 156 and Firefox 159.
`cargo test` catches regressions of our code against those captures, but not
browsers moving on. This tool does that: once a week
`.github/workflows/fingerprint-drift.yml` captures fresh Chrome stable and
Firefox release, compares them with `baseline/*.json` and keeps one
`fingerprint-drift` issue open while they differ.

Only browsers are compared, never our client: the baseline is what the
browser sent when the profiles were tuned.

## Pieces

| File | Role |
|---|---|
| `capture.sh` | Installs the browsers (`--install`), runs the scenarios, writes `versions.json` |
| `tls_sink.py` | Records each ClientHello, terminates TLS, answers h2/h1, records the requests |
| `../quic-initial-sink.py` | Records QUIC Initial datagrams |
| `ca.sh`, `page.html` | Throwaway CA for `localtest.me`; a page doing fetch GET/POST and a WebSocket |
| `normalize.py` | pcap → snapshot JSON; the only place that decides what is noise |
| `compare.py` | Snapshot vs baseline → Markdown report; exit 0 match, 1 drift, 2 incomplete |
| `issue.sh` | Opens, refreshes or closes the `fingerprint-drift` issue |
| `baseline/` | The reference snapshots (generated from `tests/data/`, never edited by hand) |

Scenarios, all against `localtest.me`: the page over h2 (port 8443), the page
over http/1.1 only (8444, Chrome opens its WebSocket connection with an
`http/1.1`-only hello there), the QUIC Initial (8445; Chrome is forced with
`--origin-to-force-quic-on`, Firefox follows the page's `Alt-Svc`). Browsers
run under Xvfb, not headless.

## What counts as noise

GREASE values, the extension order (random everywhere except Firefox over
TCP), the transport-parameter order (random in Chrome), the source connection
ID value, reserved QUIC versions, JA4's c-part (its inputs are compared one by
one), lengths, and the values of `host`/`:authority`, `origin`, `referer`,
`sec-websocket-key`, `accept-language` (the header itself, its name and
position, still counts). The platform in `user-agent` and
`sec-ch-ua-platform` is masked: the baseline was taken on macOS, CI runs on
Linux. The sink issues no TLS session tickets, so later connections are not
resumed (a resumed hello adds `pre_shared_key`).

## Run locally

Linux (or Docker) with the browsers installed:

```bash
scripts/fingerprint-drift/capture.sh --install /tmp/cap      # drop --install if present
python3 scripts/fingerprint-drift/normalize.py /tmp/cap /tmp/snap
python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline /tmp/snap /tmp/report.md
```

`CHROME=` and `FIREFOX=` pick other binaries, e.g. `CHROME=chromium` on arm64
(Google Chrome has no linux/arm64 build, and Chrome crashes under the QEMU
emulation of Docker on Apple silicon). Unit tests:
`python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests`.

## When the issue opens

1. Read the report: a new major means new UA and `sec-ch-ua` strings; a hello,
   preface or header change means the profile tables need the same change.
2. Re-measure and update `PROFILES` and the tables (the refresh checklist is
   in the comment on `PROFILES_REFRESHED_AT_UNIX`).
3. Rebuild the baseline from the new captures: put them in `tests/data/`
   (layout as `capture.sh` writes it; the CI artifact has it) together with
   `versions.json`, then
   `python3 scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/data scripts/fingerprint-drift/baseline`.
   `cargo test` checks that the baseline majors match `PROFILES`.
4. The next run closes the issue.
````

- [ ] **Step 2: README (RU)**

Create `scripts/fingerprint-drift/README.ru.md`:

````markdown
# Монитор дрейфа браузерных отпечатков

🌐 [English](README.md)

`outline-ws-rust` выдаёт себя за браузер на всех слоях, которые видит DPI:
ClientHello по TCP и QUIC, transport parameters QUIC, преамбула HTTP/2 и
заголовки запросов. Профили (`crates/outline-transport/src/fingerprint_profile.rs`
и таблицы рядом) подогнаны под Chrome 156 и Firefox 159. `cargo test` ловит
регрессии нашего кода относительно этих захватов, но не замечает, что браузеры
ушли вперёд. Это делает монитор: раз в неделю
`.github/workflows/fingerprint-drift.yml` снимает свежие Chrome stable и Firefox
release, сравнивает их с `baseline/*.json` и держит открытой одну issue
`fingerprint-drift`, пока они расходятся.

Сравниваются только браузеры, наш клиент не участвует: эталон — это то, что
браузер отправлял, когда подгоняли профили.

## Состав

| Файл | Назначение |
|---|---|
| `capture.sh` | Ставит браузеры (`--install`), гоняет сценарии, пишет `versions.json` |
| `tls_sink.py` | Записывает каждый ClientHello, терминирует TLS, отвечает по h2/h1, записывает запросы |
| `../quic-initial-sink.py` | Записывает QUIC Initial-датаграммы |
| `ca.sh`, `page.html` | Эфемерный CA для `localtest.me`; страница с fetch GET/POST и WebSocket |
| `normalize.py` | pcap → JSON-снимок; единственное место, где решается, что считать шумом |
| `compare.py` | Снимок против эталона → markdown-отчёт; код 0 — совпадает, 1 — дрейф, 2 — снимок неполный |
| `issue.sh` | Открывает, обновляет или закрывает issue `fingerprint-drift` |
| `baseline/` | Эталонные снимки (генерируются из `tests/data/`, руками не правятся) |

Сценарии, все на `localtest.me`: страница по h2 (порт 8443), страница только по
http/1.1 (8444; здесь Chrome открывает WebSocket-соединение с hello, где в ALPN
один `http/1.1`), QUIC Initial (8445; Chrome принуждается
`--origin-to-force-quic-on`, Firefox идёт по `Alt-Svc` страницы). Браузеры
работают под Xvfb, не в headless.

## Что считается шумом

GREASE-значения, порядок расширений (случайный везде, кроме Firefox по TCP),
порядок transport parameters (случайный у Chrome), значение source connection
ID, зарезервированные версии QUIC, c-часть JA4 (её исходные поля сравниваются
по отдельности), длины, значения `host`/`:authority`, `origin`, `referer`,
`sec-websocket-key`, `accept-language` (сам заголовок — имя и позиция —
сравнивается). Платформа в `user-agent` и `sec-ch-ua-platform` маскируется:
эталон снят на macOS, CI работает на Linux. Приёмник не выдаёт TLS session
tickets, поэтому последующие соединения не возобновляются (у возобновлённого
hello появляется `pre_shared_key`).

## Локальный запуск

Linux (или Docker) с браузерами:

```bash
scripts/fingerprint-drift/capture.sh --install /tmp/cap      # без --install, если браузеры уже стоят
python3 scripts/fingerprint-drift/normalize.py /tmp/cap /tmp/snap
python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline /tmp/snap /tmp/report.md
```

`CHROME=` и `FIREFOX=` задают другие бинари, например `CHROME=chromium` на arm64.
У Google Chrome нет сборки под linux/arm64, а под QEMU-эмуляцией Docker на
Apple silicon Chrome падает. Юнит-тесты:
`python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests`.

## Когда открылась issue

1. Прочитать отчёт. Новый мажор — значит, новые строки UA и `sec-ch-ua`.
   Изменение hello, преамбулы или заголовков — значит, то же изменение нужно в
   таблицах профилей.
2. Перезамерить и обновить `PROFILES` и таблицы (чеклист — в комментарии к
   `PROFILES_REFRESHED_AT_UNIX`).
3. Пересобрать эталон из новых захватов. Положить их в `tests/data/` (в
   раскладке `capture.sh`, она же лежит в артефакте CI) вместе с
   `versions.json` и выполнить
   `python3 scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/data scripts/fingerprint-drift/baseline`.
   `cargo test` проверит, что мажоры эталона совпадают с `PROFILES`.
4. Следующий прогон закроет issue.
````

- [ ] **Step 3: AGENTS.md**

В `AGENTS.md` после абзаца, который начинается с «Третий job (`feature matrix + monorepo invariants`)», добавить:

```markdown
Отдельный workflow `.github/workflows/fingerprint-drift.yml` (по понедельникам
и вручную) снимает свежие Chrome stable и Firefox release и сравнивает их
отпечаток (TCP/QUIC hello, h2-преамбула, заголовки, мажор) с эталоном
`scripts/fingerprint-drift/baseline/*.json`. При расхождении он держит открытой
одну issue `fingerprint-drift`. Обновил UA/hello в `PROFILES`
(`fingerprint_profile.rs`) — пересобери эталон из новых захватов
(`scripts/fingerprint-drift/README.ru.md`): тест
`drift_baselines_describe_the_profiled_browser_majors` сверяет мажоры.
```

- [ ] **Step 4: Спека догоняет реализацию**

В спеке заменить: «pytest на `normalize` и `compare`» → «`unittest` (stdlib)», «Python 3 без сторонних пакетов, кроме pytest для тестов» → «Python 3 только на stdlib, тесты — `unittest`», шаг workflow «pytest» → «unittest». Дописать в раздел «Workflow»: отчёт и issue на английском, публичный репозиторий. В таблице компонентов `ca.py` → `ca.sh` (openssl CLI: в stdlib нет генерации сертификатов), `tls_sink.py` пишет `<prefix>-hello.pcap` / `<prefix>-plain.pcap`. В правила нормализации и описание приёмника добавить: приёмник не выдаёт TLS session tickets (`num_tickets = 0`), чтобы последующие соединения браузера не возобновлялись. У Firefox выключен DoH, `localtest.me` пинится в `/etc/hosts`.

- [ ] **Step 5: Commit**

```bash
git add scripts/fingerprint-drift/README.md scripts/fingerprint-drift/README.ru.md AGENTS.md docs/superpowers/specs/2026-11-02-fingerprint-drift-monitor-design.md
git commit -m "docs: fingerprint drift monitor (EN/RU) and the baseline refresh rule" -- scripts/fingerprint-drift/README.md scripts/fingerprint-drift/README.ru.md AGENTS.md docs/superpowers/specs/2026-11-02-fingerprint-drift-monitor-design.md
```

---

### Task 10: Боевая проверка на GitHub

Выполняется после пуша, который делает или разрешает владелец.

- [ ] **Step 1: Ручной запуск**

```bash
gh workflow run fingerprint-drift.yml --ref main
gh run list --workflow fingerprint-drift.yml --limit 1
```

- [ ] **Step 2: Результат**

`gh run view <id> --log-failed`, если джоб красный: это сбой захвата, issue не тронута. Чинить окружение, а не эталон. Если зелёный: открыть summary прогона. Ожидаемо Chrome уже ≥ 157, поэтому появится issue `Browser fingerprint drift` с меткой `fingerprint-drift` и строкой `chrome 156 → 157`. Сверить, что в диффе нет шумовых полей.

- [ ] **Step 3: Повторный запуск не плодит issue**

Ещё раз `gh workflow run fingerprint-drift.yml --ref main`. Expected: та же issue (номер прежний) с обновлённым телом, новой не появилось.

---

## Итог выполнения (2026-11-02)

Задачи 1–9 выполнены без коммитов. Код ниже по тексту плана — исходная версия, а фактическая лежит в репозитории. Отклонения, найденные при выполнении и ревью:

- **TP `0x11`:** Chrome ставит GREASE-версию на случайное место среди версий. Для неупорядоченных браузеров `_version_information(browser, …)` сравнивает версии после выбранной как множество, эталон Chrome пересобран (Task 7).
- **TShark 4.2 (ubuntu-24.04):** QUIC JA4 печатается с префиксом `u`. `pcapread` приводит его к `q`, а тесты проходят и под 4.2.2, и под 4.6.8.
- **Пропавший вид запроса** (`h1.*`, `h2.headers.*`, `h2.priority.*`) — это код 2 (неполный захват), а не дрейф.
- **Тайминги** `SINK_SECS=30`, `BROWSER_SECS=25`. `capture.sh` падает, если QUIC-приёмник ничего не получил.
- **Захват:** пакет только с фрагментом hello пропускается.
- **Workflow:** `persist-credentials: false`, issue обновляется только с `main`. Тело issue обрезается до лимита GitHub.
- **README:** при пересборке эталона каталог `ca/` (приватный ключ) в `tests/data/` не копируется.
- **Не сделано (Minor из ревью):** сверка мажора из UA с `versions.json`; сбой захвата одного браузера скрывает дрейф другого (джоб красный целиком); `trust_anchors` сравниваются одной hex-строкой; issue-шаг не вынесен в отдельный job.
- **Task 10** (ручной запуск на GitHub) не выполнялся: нужен пуш.
