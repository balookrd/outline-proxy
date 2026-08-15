#!/usr/bin/env python3
"""Tests for the CLI: four files per user, atomic writes, the report."""

import contextlib
import io
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
    def test_writes_four_files_for_a_user_with_both_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(run(out), 0)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("both"))
        self.assertEqual(names, ["both.conf", "both.json", "both.toml", "both.txt"])

    def test_ss_only_user_gets_no_json(self):
        # ...but still gets the ws-rust config: its chain carries SS wires.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("ss-only"))
        self.assertEqual(names, ["ss-only.conf", "ss-only.toml", "ss-only.txt"])

    def test_vless_only_user_gets_no_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            names = sorted(p.name for p in out.iterdir() if p.name.startswith("vless-only"))
        self.assertEqual(names, ["vless-only.json", "vless-only.toml", "vless-only.txt"])

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

    def test_files_are_group_readable_not_world_readable_with_no_temp_left_behind(self):
        # The artifacts carry every user's password and vless_id, so they must
        # never be world-readable — only root and the serving group (www-data
        # on the node) may read them. 0640, pinned exactly regardless of umask,
        # and never even briefly wider through the temp file.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            self.assertEqual(os.stat(out / "both.conf").st_mode & 0o777, 0o640)
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
        # The flag renames the Outline artifact only: .json and .toml keep theirs.
        self.assertEqual(names, ["both.json", "both.key", "both.toml", "both.txt"])

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


class WsTomlArtifactTest(unittest.TestCase):
    def test_writes_the_ws_rust_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            self.assertEqual(run(out), 0)
            written = (out / "both.toml").read_text(encoding="utf-8")
        self.assertIn("[[outline.uplinks]]", written)
        self.assertIn("[[outline.uplinks.fallbacks]]", written)

    def test_toml_is_not_world_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            run(out)
            self.assertEqual(os.stat(out / "both.toml").st_mode & 0o777, 0o640)

    def test_report_carries_the_toml_path_and_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                run(out)
            report = buffer.getvalue()
        self.assertIn("written_toml:", report)
        self.assertIn("ws_url: https://keys.example.com/SECRET/both.toml", report)

    def test_report_warns_about_missing_server_switches(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                run(out)
            report = buffer.getvalue()
        # The golden config enables neither session_resumption nor cluster.
        self.assertIn("warning: carrier migration is inert", report)
        self.assertIn("warning: switching the active uplink will reset", report)

    def test_dry_run_writes_no_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "keys"
            run(out, "--dry-run")
            self.assertFalse(out.exists())


class OutDirResolutionTest(unittest.TestCase):
    """Where the artifacts land: the flag, else the config, else an error.

    There is no built-in default on purpose — the served directory's name is
    the only thing guarding the artifacts, so it stays in the node's
    config.toml and out of this repository.
    """

    def config_with_write_dir(self, tmp, write_dir):
        text = GOLDEN.read_text(encoding="utf-8").replace(
            "[access_keys]", f'[access_keys]\nwrite_dir = "{write_dir}"', 1
        )
        path = Path(tmp) / "config.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_missing_flag_and_missing_write_dir_is_an_error(self):
        with self.assertRaises(SystemExit) as raised:
            gk.main(["--config", str(GOLDEN), "--dry-run"])
        self.assertIn("write_dir", str(raised.exception))

    def test_write_dir_from_the_config_is_used_without_the_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "keys"
            config = self.config_with_write_dir(tmp, out)
            self.assertEqual(gk.main(["--config", str(config)]), 0)
            self.assertTrue((out / "both.conf").exists())

    def test_the_flag_wins_over_the_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            from_config = Path(tmp) / "from-config"
            from_flag = Path(tmp) / "from-flag"
            config = self.config_with_write_dir(tmp, from_config)
            gk.main(["--config", str(config), "--out-dir", str(from_flag)])
            self.assertTrue((from_flag / "both.conf").exists())
            self.assertFalse(from_config.exists())


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
