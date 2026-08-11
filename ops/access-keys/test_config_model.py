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

    def test_print_is_not_carried_into_the_model(self):
        # The golden config sets `print = false`; the generator has no report
        # for it to gate, so the field must not exist rather than sit unused.
        self.assertFalse(hasattr(self.server.access_keys, "print_report"))

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
        self.assertEqual(
            by_name(self.server, "needs sanitising/1").filename, "needs_sanitising_1"
        )

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
    BASE = """
[access_keys]
public_host = "h"

[[users]]
id = "u"
password = "p"
"""

    def load_text(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(text, encoding="utf-8")
            return cm.load(path)

    def test_no_h3_table_means_no_h3(self):
        server = self.load_text(
            '[server]\nlisten = ":443"\ncert_path = "c"\nkey_path = "k"\n' + self.BASE
        )
        self.assertFalse(server.alpn_has_h3)

    def test_h3_listen_without_any_cert_means_no_h3(self):
        server = self.load_text(
            '[server]\nlisten = ":443"\n[server.h3]\nlisten = ":443"\n' + self.BASE
        )
        self.assertFalse(server.alpn_has_h3)

    def test_explicit_empty_cert_array_opts_out_of_inheritance(self):
        text = (
            '[server]\nlisten = ":443"\n'
            '[[server.certs]]\ncert_path = "c"\nkey_path = "k"\n'
            '[server.h3]\nlisten = ":443"\ncerts = []\n' + self.BASE
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
        text = (
            '[server]\nlisten = ":443"\ncert_path = "c"\nkey_path = "k"\n[server.h3]\n'
            + self.BASE
        )
        self.assertFalse(self.load_text(text).alpn_has_h3)


if __name__ == "__main__":
    unittest.main()
