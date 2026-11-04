import json
import os
import unittest

from common import BASELINE, DATA, needs_tshark
from hello import GREASE
from normalize import (_as_set, _transport_parameters, _version_information, check_ua_major,
                       major, normalize_headers, normalize_hello, snapshot)


class RulesTest(unittest.TestCase):
    def test_major(self):
        self.assertEqual(major("Google Chrome 157.0.7900.12"), 157)
        self.assertEqual(major("Mozilla Firefox 160.0.1"), 160)
        with self.assertRaises(ValueError):
            major("Firefox")

    def test_ua_major_must_match_versions(self):
        for browser in ("chrome", "firefox"):
            with open(os.path.join(BASELINE, f"{browser}.json")) as f:
                snap = json.load(f)
            check_ua_major(snap)
            snap["major"] += 1
            with self.assertRaisesRegex(ValueError, "disagrees with versions.json"):
                check_ua_major(snap)

    def test_set_keeps_grease_count(self):
        self.assertEqual(_as_set([GREASE, 16, 0, GREASE, 5]), [0, 5, 16, GREASE, GREASE])

    def test_version_information_firefox_keeps_order(self):
        self.assertEqual(_version_information("firefox", "00000001ea9aaa3a6b3343cf"),
                         ["00000001", GREASE, "6b3343cf"])

    def test_version_information_chrome_ignores_reserved_position(self):
        expected = ["00000001", "00000001", GREASE]
        self.assertEqual(_version_information("chrome", "00000001ea9aaa3a00000001"), expected)
        self.assertEqual(_version_information("chrome", "0000000100000001ea9aaa3a"), expected)

    def test_transport_parameters_firefox_keep_order(self):
        tps = [[15, "acaa3d"], [1, "80007530"], [GREASE, None]]
        self.assertEqual(_transport_parameters("firefox", tps),
                         [[15, "len:3"], [1, "80007530"], [GREASE, None]])

    def test_transport_parameters_chrome_sorted(self):
        tps = [[GREASE, None], [9, "4064"], [1, "80007530"], [15, ""]]
        self.assertEqual(_transport_parameters("chrome", tps),
                         [[1, "80007530"], [9, "4064"], [15, "len:0"], [GREASE, None]])

    def test_extension_order_compared_only_for_firefox_tcp(self):
        record = {"ja4": "t13d1517h2_8daaf6152771_63ff51340b64",
                  "hello": {"extensions": [16, GREASE, 0], "transport_parameters": None}}
        self.assertEqual(normalize_hello("chrome", "tcp", record)["extensions"], [0, 16, GREASE])
        self.assertEqual(normalize_hello("firefox", "tcp", record)["extensions"], [16, GREASE, 0])
        self.assertEqual(normalize_hello("firefox", "quic", record)["extensions"],
                         [0, 16, GREASE])
        self.assertEqual(normalize_hello("chrome", "tcp", record)["ja4_ab"],
                         "t13d1517h2_8daaf6152771")

    def test_headers_drop_platform_and_volatile_values(self):
        headers = [
            [":authority", "localtest.me:8443"],
            ["user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                           "HeadlessChrome/157.0.0.0 Safari/537.36"],
            ["sec-ch-ua-platform", "\"Linux\""],
            ["Accept-Language", "ru-RU,ru;q=0.9"],
            ["accept", "*/*"],
        ]
        self.assertEqual(normalize_headers(headers), [
            [":authority", "<volatile>"],
            ["user-agent", "Mozilla/5.0 (<platform>) AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/157.0.0.0 Safari/537.36"],
            ["sec-ch-ua-platform", "<platform>"],
            ["Accept-Language", "<volatile>"],
            ["accept", "*/*"],
        ])


@needs_tshark
class BaselineTest(unittest.TestCase):
    """The committed baselines are exactly what normalize.py makes of the
    2026-10-29…31 captures in tests/data."""

    def check(self, browser):
        with open(os.path.join(DATA, "versions.json")) as f:
            version_line = json.load(f)[browser]
        with open(os.path.join(BASELINE, f"{browser}.json")) as f:
            baseline = json.load(f)
        # Round-trip through JSON: tuples and lists compare alike there.
        got = json.loads(json.dumps(snapshot(DATA, browser, version_line)))
        self.assertEqual(got, baseline)

    def test_chrome(self):
        self.check("chrome")

    def test_firefox(self):
        self.check("firefox")


if __name__ == "__main__":
    unittest.main()
