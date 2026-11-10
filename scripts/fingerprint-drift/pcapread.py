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
    return None


def _quic_ja4(ja4):
    # TShark < 4.4 (4.2 on the ubuntu-24.04 runners) prints the QUIC JA4
    # transport char as `u`; newer versions print `q`. Canonicalize to `q`.
    if ja4 and ja4.startswith("u"):
        return "q" + ja4[1:]
    return ja4


def _first(layers, *keys):
    for key in keys:
        for v in _find(layers, key):
            return v
    return None


def client_hellos(pcap):
    """Every ClientHello in capture order: {"port", "ja4", "hello"}."""
    decode = _decode_as(pcap, "tls", "quic")
    quic = decode.endswith(",quic")
    out = []
    for layers in _packets(pcap, decode, "tls.handshake.type==1", raw=True):
        hello = _complete_hello(_find(layers, "tls.handshake_raw"))
        if hello is None:
            continue  # only a fragment of a split hello: skip, not abort
        ja4 = _first(layers, "tls.handshake.ja4")
        record = {
            "port": int(_first(layers, "tcp.srcport", "udp.srcport")),
            "ja4": _quic_ja4(ja4) if quic else ja4,
            "hello": parse_client_hello(hello),
        }
        if quic:
            # Destination CID length of the Initial: cleartext in the long header.
            record["dcid_len"] = int(_first(layers, "quic.dcil"))
        out.append(record)
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
