#!/usr/bin/env python3
"""Tests for the CLI: three files per user, atomic writes, the report."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import generate_keys as gk  # noqa: E402

GOLDEN = HERE / "golden" / "config.toml"


def run(out_dir, *extra):
    return gk.main(["--config", str(GOLDEN), "--out-dir", str(out_dir), *extra])


class MainTest(unittest.TestCase):
    def test_writes_three_files_for_a_user_with_both_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(run(out), 0)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("both"))
        self.assertEqual(names, ["both.conf", "both.json", "both.txt"])

    def test_ss_only_user_gets_no_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("ss-only"))
        self.assertEqual(names, ["ss-only.conf", "ss-only.txt"])

    def test_vless_only_user_gets_no_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("vless-only"))
        self.assertEqual(names, ["vless-only.json", "vless-only.txt"])

    def test_disabled_user_gets_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = [p.name for p in out.iterdir() if p.name.startswith("disabled")]
        self.assertEqual(names, [])

    def test_no_legacy_per_carrier_files_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = [p.name for p in out.iterdir()]
        self.assertFalse([n for n in names if "-vless-" in n or "-ss-" in n])

    def test_txt_content_matches_the_artifact_layer(self):
        import artifacts
        import config_model as cm

        server = cm.load(GOLDEN)
        user = next(u for u in server.users if u.name == "both")
        expected = (
            "\n".join(artifacts.user_urls(user, server.access_keys, server.alpn_has_h3))
            + "\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            actual = (out / "both.txt").read_text(encoding="utf-8")
        self.assertEqual(actual, expected)

    def test_json_is_a_single_element_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            payload = json.loads((out / "both.json").read_text(encoding="utf-8"))
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["outbounds"][0]["tag"], "cloud1-xhttp-h3")

    def test_conf_matches_the_golden_artifact(self):
        golden = (HERE / "golden" / "expected" / "both.conf").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            actual = (out / "both.conf").read_text(encoding="utf-8")
        self.assertEqual(actual, golden)

    def test_files_are_world_readable_with_no_temp_left_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            self.assertEqual(os.stat(out / "both.conf").st_mode & 0o777, 0o644)
            self.assertFalse([p.name for p in out.iterdir() if p.name.startswith(".")])

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "keys"
            self.assertEqual(run(out, "--dry-run"), 0)
            self.assertFalse(out.exists())

    def test_file_extension_flag_overrides_the_config(self):
        # Production passes the extension as a flag: config.toml on the nodes
        # has no `file_extension`, and save-keys.sh handed the binary
        # `--access-key-file-extension .conf`. Reading only the config would
        # silently write <user>.yaml and 404 every client.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out, "--file-extension", ".key")
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("both"))
        self.assertEqual(names, ["both.json", "both.key", "both.txt"])

    def test_file_extension_flag_reaches_the_ssconf_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out, "--file-extension", ".key")
            first_line = (out / "both.txt").read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(first_line, "ssconf://keys.example.com/SECRET/both.key")

    def test_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            first = (out / "both.txt").read_text(encoding="utf-8")
            run(out)
            self.assertEqual((out / "both.txt").read_text(encoding="utf-8"), first)


class ReportTest(unittest.TestCase):
    def test_report_has_one_block_per_user(self):
        report = gk.render_report(
            [
                {
                    "user": "both",
                    "conf": "/out/both.conf",
                    "json": "/out/both.json",
                    "txt": "/out/both.txt",
                    "outline_url": "ssconf://h/SECRET/both.conf",
                    "happ_url": "https://h/SECRET/both.json",
                }
            ]
        )
        self.assertEqual(
            report,
            "user: both\n"
            "written_conf: /out/both.conf\n"
            "written_json: /out/both.json\n"
            "written_txt: /out/both.txt\n"
            "outline_url: ssconf://h/SECRET/both.conf\n"
            "happ_url: https://h/SECRET/both.json\n",
        )

    def test_report_carries_no_config_url(self):
        # It duplicated outline_url modulo the scheme, and the same link is the
        # first line of <user>.txt.
        report = gk.render_report(
            [{"user": "b", "txt": "/b.txt", "config_url": "https://h/b.conf"}]
        )
        self.assertNotIn("config_url", report)

    def test_absent_fields_are_omitted(self):
        report = gk.render_report([{"user": "v", "json": "/out/v.json", "txt": "/out/v.txt"}])
        self.assertEqual(report, "user: v\nwritten_json: /out/v.json\nwritten_txt: /out/v.txt\n")

    def test_report_from_the_real_config_carries_both_urls(self):
        import artifacts
        import config_model as cm

        server = cm.load(GOLDEN)
        ak = server.access_keys
        user = next(u for u in server.users if u.name == "both")
        report = gk.render_report(
            [
                {
                    "user": user.name,
                    "outline_url": artifacts.outline_url(user, ak),
                    "happ_url": artifacts.happ_url(user, ak),
                }
            ]
        )
        self.assertIn("outline_url: ssconf://keys.example.com/SECRET/both.conf\n", report)
        self.assertIn("happ_url: https://keys.example.com/SECRET/both.json\n", report)

    def test_blocks_are_separated_by_a_blank_line(self):
        report = gk.render_report([{"user": "a", "txt": "/a.txt"}, {"user": "b", "txt": "/b.txt"}])
        self.assertEqual(report, "user: a\nwritten_txt: /a.txt\n\nuser: b\nwritten_txt: /b.txt\n")


if __name__ == "__main__":
    unittest.main()
