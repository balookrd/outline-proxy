import copy
import json
import os
import tempfile
import unittest

from common import BASELINE
from compare import (DRIFT, DRIFT_AND_INCOMPLETE, INCOMPLETE, MATCH, diff, main,
                     report_browser)


def load(browser):
    with open(os.path.join(BASELINE, f"{browser}.json")) as f:
        return json.load(f)


class DiffTest(unittest.TestCase):
    def test_nested_paths(self):
        self.assertEqual(diff({"a": {"b": 1, "c": [1]}}, {"a": {"b": 2, "c": [1]}}),
                         [("a.b", 1, 2)])
        self.assertEqual(diff({"a": 1}, {"a": 1, "b": 2}), [("b", None, 2)])


class ReportTest(unittest.TestCase):
    def test_identical_snapshot_matches(self):
        code, _ = report_browser("chrome", load("chrome"), load("chrome"))
        self.assertEqual(code, MATCH)

    def test_changed_field_is_drift(self):
        snap = load("chrome")
        snap["quic"]["sig_algs"] = snap["quic"]["sig_algs"] + [2055]
        code, lines = report_browser("chrome", load("chrome"), snap)
        self.assertEqual(code, DRIFT)
        self.assertTrue(any(ln.startswith("- `quic.sig_algs`") for ln in lines), lines)

    def test_new_major_gets_its_own_line(self):
        snap = load("firefox")
        snap["major"] += 1
        code, lines = report_browser("firefox", load("firefox"), snap)
        self.assertEqual(code, DRIFT)
        self.assertTrue(any("firefox 159 → 160" in ln for ln in lines), lines)

    def test_list_change_names_added_and_removed(self):
        snap = load("chrome")
        snap["tcp_h2"]["trust_anchors"] = snap["tcp_h2"]["trust_anchors"][1:] + ["d6790910"]
        _, lines = report_browser("chrome", load("chrome"), snap)
        self.assertIn('- `tcp_h2.trust_anchors`: `+["d6790910"] -["82df130201"]`', lines)

    def test_reordered_list_shows_both_orders(self):
        snap = load("firefox")
        snap["tcp_h2"]["extensions"] = snap["tcp_h2"]["extensions"][::-1]
        _, lines = report_browser("firefox", load("firefox"), snap)
        self.assertTrue(any(ln.startswith("- `tcp_h2.extensions`: `[") and "→" in ln
                            for ln in lines), lines)

    def test_header_change_is_a_line_diff(self):
        snap = load("chrome")
        snap["h1"]["ws"] = snap["h1"]["ws"] + [["Priority", "u=0"]]
        _, lines = report_browser("chrome", load("chrome"), snap)
        self.assertIn("+Priority: u=0", lines)

    def test_missing_layer_is_incomplete(self):
        snap = copy.deepcopy(load("chrome"))
        snap["quic"] = None
        code, _ = report_browser("chrome", load("chrome"), snap)
        self.assertEqual(code, INCOMPLETE)

    def test_missing_request_kind_is_incomplete(self):
        snap = copy.deepcopy(load("chrome"))
        del snap["h1"]["ws"]
        code, lines = report_browser("chrome", load("chrome"), snap)
        self.assertEqual(code, INCOMPLETE)
        self.assertIn("h1.ws", " ".join(lines))
        snap = copy.deepcopy(load("chrome"))
        del snap["h2"]["headers"]["navigate"]
        code, lines = report_browser("chrome", load("chrome"), snap)
        self.assertEqual(code, INCOMPLETE)
        self.assertIn("h2.headers.navigate", " ".join(lines))

    def test_missing_snapshot_is_incomplete(self):
        code, _ = report_browser("chrome", load("chrome"), None)
        self.assertEqual(code, INCOMPLETE)


class MainTest(unittest.TestCase):
    def run_main(self, snapshots):
        with tempfile.TemporaryDirectory() as snaps:
            for browser, snap in snapshots.items():
                with open(os.path.join(snaps, f"{browser}.json"), "w") as f:
                    json.dump(snap, f)
            report = os.path.join(snaps, "report.md")
            code = main(["compare.py", BASELINE, snaps, report])
            with open(report) as f:
                return code, f.read()

    def test_codes(self):
        drifted = load("chrome")
        drifted["major"] += 1
        self.assertEqual(self.run_main({"chrome": load("chrome"), "firefox": load("firefox")})[0],
                         MATCH)
        self.assertEqual(self.run_main({"chrome": drifted, "firefox": load("firefox")})[0], DRIFT)
        self.assertEqual(self.run_main({"chrome": load("chrome")})[0], INCOMPLETE)

    def test_drift_is_reported_beside_a_failed_capture(self):
        snap = load("chrome")
        snap["major"] += 1
        # firefox.json is missing: the code says both, the report keeps chrome's drift.
        code, report = self.run_main({"chrome": snap})
        self.assertEqual(code, DRIFT_AND_INCOMPLETE)
        self.assertIn("## chrome: drift", report)
        self.assertIn("Snapshot missing", report)


if __name__ == "__main__":
    unittest.main()
