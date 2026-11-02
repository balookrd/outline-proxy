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

HOLD = 8.0  # the page starts its requests 2 s in (page.html)
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
