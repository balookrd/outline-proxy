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
