#!/usr/bin/env python3
"""Golden comparison: Python must reproduce the binary's artifacts exactly."""

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import artifacts  # noqa: E402
import config_model as cm  # noqa: E402

GOLDEN = HERE / "golden" / "config.toml"
EXPECTED = HERE / "golden" / "expected"


def golden_files():
    return sorted(p.name for p in EXPECTED.iterdir() if p.is_file())


class GoldenTest(unittest.TestCase):
    def setUp(self):
        self.server = cm.load(GOLDEN)
        self.ak = self.server.access_keys
        self.produced = {}
        for user in self.server.users:
            for artifact in artifacts.legacy_artifacts(
                user, self.ak, self.server.alpn_has_h3
            ):
                self.produced[artifact.name + self.ak.file_extension] = artifact.content

    def test_produces_exactly_the_same_file_names(self):
        self.assertEqual(sorted(self.produced), golden_files())

    def test_every_file_matches_byte_for_byte(self):
        for name in golden_files():
            with self.subTest(artifact=name):
                self.assertEqual(
                    self.produced[name], (EXPECTED / name).read_text(encoding="utf-8")
                )


class UserUrlsTest(unittest.TestCase):
    def setUp(self):
        self.server = cm.load(GOLDEN)
        self.ak = self.server.access_keys

    def user(self, name):
        return next(u for u in self.server.users if u.name == name)

    def test_txt_starts_with_ssconf_then_lists_every_uri(self):
        lines = artifacts.user_urls(self.user("both"), self.ak, self.server.alpn_has_h3)
        self.assertTrue(lines[0].startswith("ssconf://"))
        self.assertEqual(len(lines), 7)
        self.assertEqual(
            [line.split("#", 1)[1] for line in lines[1:]],
            [
                "keys:both-ss-ws",
                "keys:both-ss-xhttp-packet-up",
                "keys:both-ss-xhttp-stream-one",
                "keys:both-vless-ws",
                "keys:both-vless-xhttp-packet-up",
                "keys:both-vless-xhttp-stream-one",
            ],
        )

    def test_txt_lines_are_exactly_the_legacy_uris(self):
        # The .txt file must be a repackaging, never a re-rendering.
        user = self.user("own-paths")
        legacy = artifacts.legacy_artifacts(user, self.ak, self.server.alpn_has_h3)
        uris = [
            a.content.rstrip("\n")
            for a in legacy
            if a.content.startswith(("ss://", "vless://"))
        ]
        lines = artifacts.user_urls(user, self.ak, self.server.alpn_has_h3)
        self.assertEqual(lines[1:], uris)

    def test_vless_only_user_has_no_ssconf_line(self):
        lines = artifacts.user_urls(
            self.user("vless-only"), self.ak, self.server.alpn_has_h3
        )
        self.assertFalse(any(line.startswith("ssconf://") for line in lines))
        self.assertEqual(len(lines), 3)

    def test_ss_only_user_has_no_vless_lines(self):
        lines = artifacts.user_urls(self.user("ss-only"), self.ak, self.server.alpn_has_h3)
        self.assertFalse(any("vless" in line for line in lines))


class UrlHelpersTest(unittest.TestCase):
    def setUp(self):
        self.server = cm.load(GOLDEN)
        self.ak = self.server.access_keys
        self.user = next(u for u in self.server.users if u.name == "both")

    def test_config_url_uses_the_sanitised_filename(self):
        self.assertEqual(
            artifacts.config_url(self.user, self.ak),
            "https://keys.example.com/SECRET/both.conf",
        )

    def test_access_key_url_is_the_ssconf_form(self):
        self.assertEqual(
            artifacts.access_key_url(self.user, self.ak),
            "ssconf://keys.example.com/SECRET/both.conf",
        )


if __name__ == "__main__":
    unittest.main()
