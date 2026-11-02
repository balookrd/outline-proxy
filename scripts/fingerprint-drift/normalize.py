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
