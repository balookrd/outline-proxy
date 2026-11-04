import os
import unittest

from common import DATA, needs_tshark
from pcapread import _complete_hello, _quic_ja4, client_hellos, h1_requests, h2_connections


def pcap(browser, name):
    return os.path.join(DATA, browser, name)


class HelpersTest(unittest.TestCase):
    def test_old_tshark_quic_prefix_is_canonicalized(self):
        self.assertEqual(_quic_ja4("u13d0312h3_aa_bb"), "q13d0312h3_aa_bb")
        self.assertEqual(_quic_ja4("q13d0312h3_aa_bb"), "q13d0312h3_aa_bb")
        self.assertIsNone(_quic_ja4(None))

    def test_fragment_is_not_a_complete_hello(self):
        full = bytes([1, 0, 0, 3, 9, 9, 9])
        self.assertIsNone(_complete_hello([[[full[:5].hex(), 0, 5, 0, 0]]]))
        self.assertEqual(_complete_hello([[full[:5].hex(), 0, 5, 0, 0], [full.hex(), 0, 7, 0, 0]]), full)


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
        # Chrome may preconnect: the first connection carrying a request.
        frames = next(fr for fr in conns.values() if any(f["type"] == 1 for f in fr))
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
