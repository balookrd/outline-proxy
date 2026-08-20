#!/usr/bin/env python3
"""Golden comparison for the artifacts this module assembles.

The Python generator is the source of truth now that Rust generation is gone;
golden/expected is its byte-for-byte snapshot. This file pins the two artifact
kinds `artifacts` owns — the Outline `.conf` and the `.txt` URL list. The
`.json` and `.toml` are pinned by test_xray_json and test_ws_toml; the whole
set is pinned by test_generate_keys.GoldenCorpusTest.
"""

import sys
import unittest
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import artifacts  # noqa: E402
import config_model as cm  # noqa: E402

GOLDEN = HERE / "golden" / "config.toml"
EXPECTED = HERE / "golden" / "expected"


class GoldenTest(unittest.TestCase):
    """The Outline `.conf` and `.txt` artifacts match the golden corpus.

    `legacy_artifacts` still feeds `user_urls`, so its per-carrier URIs stay
    anchored byte-for-byte through every `<user>.txt` even though the generator
    no longer emits a file per carrier.
    """

    def setUp(self):
        self.server = cm.load(GOLDEN)
        self.ak = self.server.access_keys

    def test_conf_matches_the_golden_corpus(self):
        for user in self.server.users:
            content = artifacts.outline_artifact(user, self.ak)
            path = EXPECTED / f"{user.filename}{self.ak.file_extension}"
            with self.subTest(user=user.filename):
                if content is None:
                    self.assertFalse(path.exists())
                else:
                    self.assertEqual(content, path.read_text(encoding="utf-8"))

    def test_txt_matches_the_golden_corpus(self):
        for user in self.server.users:
            urls = artifacts.user_urls(user, self.ak, self.server.alpn_has_h3)
            path = EXPECTED / f"{user.filename}.txt"
            with self.subTest(user=user.filename):
                if urls:
                    self.assertEqual(
                        "\n".join(urls) + "\n", path.read_text(encoding="utf-8")
                    )
                else:
                    self.assertFalse(path.exists())


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

    def user(self, name):
        return next(u for u in self.server.users if u.name == name)

    def test_config_url_uses_the_sanitised_filename(self):
        self.assertEqual(
            artifacts.config_url(self.user("both"), self.ak),
            "https://keys.example.com/SECRET/both.conf",
        )

    def test_outline_url_is_the_ssconf_form(self):
        self.assertEqual(
            artifacts.outline_url(self.user("both"), self.ak),
            "ssconf://keys.example.com/SECRET/both.conf",
        )

    def test_outline_url_absent_without_a_password(self):
        self.assertIsNone(artifacts.outline_url(self.user("vless-only"), self.ak))

    def test_happ_url_points_at_the_json_subscription(self):
        self.assertEqual(
            artifacts.happ_url(self.user("both"), self.ak),
            "https://keys.example.com/SECRET/both.json",
        )

    def test_happ_url_keeps_the_json_extension_regardless_of_file_extension(self):
        # file_extension applies to the Outline artifact only; the subscription
        # is always <user>.json.
        self.assertTrue(artifacts.happ_url(self.user("both"), self.ak).endswith(".json"))

    def test_happ_url_absent_without_a_vless_subscription(self):
        self.assertIsNone(artifacts.happ_url(self.user("ss-only"), self.ak))

    def test_happ_url_uses_the_sanitised_filename(self):
        self.assertEqual(
            artifacts.happ_url(self.user("needs sanitising/1"), self.ak),
            "https://keys.example.com/SECRET/needs_sanitising_1.json",
        )

    def test_ws_url_points_at_the_toml_config(self):
        self.assertEqual(
            artifacts.ws_url(self.user("both"), self.ak),
            "https://keys.example.com/SECRET/both.toml",
        )

    def test_ws_url_covers_an_ss_only_user(self):
        # The ws-rust chain also carries SS wires, so an SS-only user gets a
        # config even though they get no Xray subscription.
        self.assertEqual(
            artifacts.ws_url(self.user("ss-only"), self.ak),
            "https://keys.example.com/SECRET/ss-only.toml",
        )

    def test_no_ws_url_without_wires(self):
        # Every enabled user in the golden config inherits the global SS/VLESS
        # paths, so an undialable user has to be built by hand.
        bare = replace(self.user("ss-only"), password=None, vless_id=None)
        self.assertIsNone(artifacts.ws_url(bare, self.ak))


if __name__ == "__main__":
    unittest.main()
