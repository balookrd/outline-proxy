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
