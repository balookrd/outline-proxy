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
        self.assertEqual(uri.percent_encode_fragment("host:user"), "host:user")

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
        self.assertEqual(
            uri.authority_with_default_port("example.com", 443), "example.com:443"
        )

    def test_keeps_an_explicit_port_on_a_bracketed_ipv6(self):
        self.assertEqual(
            uri.authority_with_default_port("[::1]:8443", 443), "[::1]:8443"
        )

    def test_a_dns_host_with_a_port_is_bracketed_like_rust_does(self):
        # Quirk of the Rust implementation, reproduced deliberately:
        # normalize_host only recognises a port when the part before the colon
        # parses as IPv6, so "example.com:8443" falls through to the
        # wrap-in-brackets branch and then gets the default port appended.
        # Deployments set `public_host` without a port, so this never fires in
        # practice — but the port is byte-equivalence, not taste.
        self.assertEqual(
            uri.authority_with_default_port("example.com:8443", 443),
            "[example.com:8443]:443",
        )


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
            uri.vless_ws_uri(
                self.UUID, self.HOST, "wss", "/GLOBAL/vless", "bob", "h3,h2,http/1.1"
            ),
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
            uri.ss_ws_uri(
                "aes-128-gcm", "pw", self.HOST, "wss", "/GLOBAL/ss", "bob", "h2,http/1.1"
            ),
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
                "vless://11111111-1111-4111-8111-111111111111@keys.example.com:80"
                "?type=ws&security=none&path="
            )
        )


if __name__ == "__main__":
    unittest.main()
