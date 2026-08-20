#!/usr/bin/env python3
"""Tests for outline_yaml.py, checked against the golden corpus."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import config_model as cm  # noqa: E402
import outline_yaml  # noqa: E402

GOLDEN_CONFIG = HERE / "golden" / "config.toml"
GOLDEN_DIR = HERE / "golden" / "expected"


class WebsocketUrlTest(unittest.TestCase):
    def test_builds_a_wss_url(self):
        self.assertEqual(
            outline_yaml.websocket_url("wss", "keys.example.com", "/GLOBAL/tcp"),
            "wss://keys.example.com/GLOBAL/tcp",
        )

    def test_adds_the_leading_slash(self):
        self.assertEqual(
            outline_yaml.websocket_url("wss", "keys.example.com", "GLOBAL/tcp"),
            "wss://keys.example.com/GLOBAL/tcp",
        )


class RenderTest(unittest.TestCase):
    def test_matches_the_golden_outline_artifact(self):
        expected = (GOLDEN_DIR / "both.conf").read_text(encoding="utf-8")
        actual = outline_yaml.render(
            "chacha20-ietf-poly1305",
            "pw-both",
            "wss://keys.example.com/GLOBAL/tcp",
            "wss://keys.example.com/GLOBAL/udp",
        )
        self.assertEqual(actual, expected)

    def test_matches_the_golden_artifact_for_a_2022_method(self):
        expected = (GOLDEN_DIR / "own-method.conf").read_text(encoding="utf-8")
        actual = outline_yaml.render(
            "2022-blake3-chacha20-poly1305",
            "cGFzc3dvcmQtMzItYnl0ZXMtZm9yLTIwMjIta2V5cw==",
            "wss://keys.example.com/GLOBAL/tcp",
            "wss://keys.example.com/GLOBAL/udp",
        )
        self.assertEqual(actual, expected)

    def test_quotes_are_escaped(self):
        rendered = outline_yaml.render('a"b', "p", "u", "u")
        self.assertIn('cipher: "a\\"b"', rendered)


class GoldenConfTest(unittest.TestCase):
    """Every `.conf` in the golden corpus is reproducible from render().

    Broader than the two hand-picked cases above: it walks the synthetic config
    and pins the Outline artifact for every user that has a password, and
    asserts the VLESS-only user gets none.
    """

    def test_every_golden_conf_reproduces(self):
        server = cm.load(GOLDEN_CONFIG)
        ak = server.access_keys
        for user in server.users:
            path = GOLDEN_DIR / f"{user.filename}{ak.file_extension}"
            with self.subTest(user=user.filename):
                if user.password is None:
                    self.assertFalse(path.exists())
                    continue
                actual = outline_yaml.render(
                    user.method,
                    user.password,
                    outline_yaml.websocket_url(
                        ak.public_scheme, ak.public_host, user.ws_path_tcp
                    ),
                    outline_yaml.websocket_url(
                        ak.public_scheme, ak.public_host, user.ws_path_udp
                    ),
                )
                self.assertEqual(actual, path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
