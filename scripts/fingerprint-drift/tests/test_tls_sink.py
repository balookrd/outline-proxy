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
