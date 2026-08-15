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

    def test_write_dir_is_none_when_the_config_does_not_set_it(self):
        # The golden config names no output directory: the served path is a
        # secret and never lives in this repository.
        self.assertIsNone(self.server.access_keys.write_dir)

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


class UrlBaseDerivationTest(unittest.TestCase):
    """`url_base` is `public_host` + the served directory, so it need not be said twice."""

    def load_text(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(text, encoding="utf-8")
            return cm.load(path)

    USERS = """
[[users]]
id = "u"
password = "p"
"""

    def test_derived_from_host_and_write_dir(self):
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n'
            'write_dir = "/var/www/html/SECRET/"\n' + self.USERS
        )
        self.assertEqual(server.access_keys.url_base, "https://h.example.com/SECRET")

    def test_explicit_url_base_wins(self):
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n'
            'url_base = "https://other.example.com/ELSEWHERE"\n'
            'write_dir = "/var/www/html/SECRET/"\n' + self.USERS
        )
        self.assertEqual(
            server.access_keys.url_base, "https://other.example.com/ELSEWHERE"
        )

    def test_plain_ws_scheme_derives_http(self):
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\npublic_scheme = "ws"\n'
            'write_dir = "/var/www/html/SECRET/"\n' + self.USERS
        )
        self.assertEqual(server.access_keys.url_base, "http://h.example.com/SECRET")

    def test_trailing_slash_does_not_leak_into_the_url(self):
        without = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n'
            'write_dir = "/var/www/html/SECRET"\n' + self.USERS
        )
        self.assertEqual(without.access_keys.url_base, "https://h.example.com/SECRET")

    def test_nested_directory_keeps_the_whole_path_below_the_webroot(self):
        # Taking only the last segment would build /prod instead of /keys/prod:
        # artifacts written correctly, links pointing nowhere, no error.
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n'
            'write_dir = "/var/www/html/keys/prod/"\n' + self.USERS
        )
        self.assertEqual(server.access_keys.url_base, "https://h.example.com/keys/prod")

    def test_directory_outside_the_webroot_derives_nothing(self):
        # The URL path cannot be known from a filesystem path alone; refuse
        # loudly (no links at all) rather than inventing a wrong one.
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n'
            'write_dir = "/srv/elsewhere/SECRET"\n' + self.USERS
        )
        self.assertIsNone(server.access_keys.url_base)

    def test_webroot_itself_derives_nothing(self):
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n'
            'write_dir = "/var/www/html"\n' + self.USERS
        )
        self.assertIsNone(server.access_keys.url_base)

    def test_no_write_dir_leaves_url_base_unset(self):
        # Nothing to derive from: the user simply gets no ssconf/happ links.
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n' + self.USERS
        )
        self.assertIsNone(server.access_keys.url_base)

    def test_scheme_defaults_to_wss_when_absent(self):
        server = self.load_text(
            '[access_keys]\npublic_host = "h.example.com"\n'
            'write_dir = "/var/www/html/SECRET"\n' + self.USERS
        )
        self.assertEqual(server.access_keys.public_scheme, "wss")


class SanitizeTest(unittest.TestCase):
    def test_keeps_safe_characters(self):
        self.assertEqual(cm.sanitize_filename("a.b_c-1"), "a.b_c-1")

    def test_replaces_everything_else(self):
        self.assertEqual(cm.sanitize_filename("a/b c:d"), "a_b_c_d")

    def test_empty_becomes_user(self):
        self.assertEqual(cm.sanitize_filename(""), "user")


class WriteDirTest(unittest.TestCase):
    def test_write_dir_is_read_from_the_access_keys_section(self):
        text = (
            '[access_keys]\npublic_host = "h"\nwrite_dir = "/var/www/html/KEYS"\n'
            '\n[[users]]\nid = "u"\npassword = "p"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(text, encoding="utf-8")
            server = cm.load(path)
        self.assertEqual(server.access_keys.write_dir, "/var/www/html/KEYS")


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


class ServerFeaturesTest(unittest.TestCase):
    BASE = """
[access_keys]
public_host = "keys.example.com"

[[users]]
id = "alice"
password = "pw"
"""

    def load_body(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(body, encoding="utf-8")
            return cm.load(path)

    def test_features_default_to_off(self):
        server = self.load_body(self.BASE)
        self.assertFalse(server.padding.enabled)
        self.assertEqual(server.padding.paths, ())
        self.assertFalse(server.session_resumption.enabled)
        self.assertEqual(server.session_resumption.downlink_buffer_bytes, 0)
        self.assertFalse(server.cluster_enabled)

    def test_reads_padding_paths(self):
        server = self.load_body(
            self.BASE
            + """
[padding]
enabled = true
paths = ["/GLOBAL/ss", "/GLOBAL/ssx"]
"""
        )
        self.assertTrue(server.padding.enabled)
        self.assertEqual(server.padding.paths, ("/GLOBAL/ss", "/GLOBAL/ssx"))

    def test_padding_paths_without_enabled_stay_inactive(self):
        server = self.load_body(
            self.BASE
            + """
[padding]
paths = ["/GLOBAL/ss"]
"""
        )
        self.assertFalse(server.padding.enabled)
        self.assertEqual(server.padding.paths, ("/GLOBAL/ss",))

    def test_reads_session_resumption(self):
        server = self.load_body(
            self.BASE
            + """
[session_resumption]
enabled = true
downlink_buffer_bytes = 65536
"""
        )
        self.assertTrue(server.session_resumption.enabled)
        self.assertEqual(server.session_resumption.downlink_buffer_bytes, 65536)

    def test_cluster_needs_explicit_enabled(self):
        without_flag = self.load_body(
            self.BASE
            + """
[cluster]
shard_id = 1
"""
        )
        self.assertFalse(without_flag.cluster_enabled)

        enabled = self.load_body(
            self.BASE
            + """
[cluster]
enabled = true
shard_id = 1
"""
        )
        self.assertTrue(enabled.cluster_enabled)


if __name__ == "__main__":
    unittest.main()
