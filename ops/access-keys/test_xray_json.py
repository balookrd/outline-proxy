#!/usr/bin/env python3
"""Offline tests for xray_json.py. Stdlib only; no network, no node access.

Config parsing is covered by test_config_model.py and file writing by
test_generate_keys.py — this module only checks the rendered document.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import xray_json as gen  # noqa: E402
from config_model import User  # noqa: E402

HERE = Path(__file__).resolve().parent
GOLDEN_CONFIG = HERE / "golden" / "config.toml"
GOLDEN_DIR = HERE / "golden" / "expected"

NODES = ("cloud1.beerloga.su", "cloud2.beerloga.su")
UUID = "11111111-1111-4111-8111-111111111111"


def make_user(name="alice", xhttp="/OTHER/xhttp", ws="/SECRET/vless"):
    return User(
        name=name,
        filename=name,
        password=None,
        method="chacha20-ietf-poly1305",
        vless_id=UUID,
        ws_path_tcp="/t",
        ws_path_udp="/u",
        ws_path_vless=ws,
        ws_path_ss=None,
        xhttp_path_vless=xhttp,
        xhttp_path_ss=None,
    )


def build(xhttp="/OTHER/xhttp", ws="/SECRET/vless"):
    return gen.build_outbounds(UUID, xhttp, ws, NODES)


class BuildOutboundsTest(unittest.TestCase):
    def test_tag_order_puts_proxies_first_and_direct_last(self):
        tags = [o["tag"] for o in build()]
        self.assertEqual(
            tags,
            [
                "cloud1-xhttp-h3",
                "cloud2-xhttp-h3",
                "cloud1-xhttp-h2",
                "cloud2-xhttp-h2",
                "cloud1-ws",
                "cloud2-ws",
                "direct",
                "block",
            ],
        )

    def test_first_outbound_is_never_direct(self):
        # leastPing routes to outbounds[0] until the first probe lands.
        self.assertNotEqual(build()[0]["tag"], "direct")

    def test_h3_legs_carry_exactly_h3(self):
        for outbound in build():
            if outbound["tag"].endswith("-xhttp-h3"):
                self.assertEqual(
                    outbound["streamSettings"]["tlsSettings"]["alpn"], ["h3"]
                )

    def test_h2_legs_carry_exactly_h2(self):
        for outbound in build():
            if outbound["tag"].endswith("-xhttp-h2"):
                self.assertEqual(
                    outbound["streamSettings"]["tlsSettings"]["alpn"], ["h2"]
                )

    def test_ws_legs_carry_http11_because_xray_cannot_do_rfc8441(self):
        for outbound in build():
            if outbound["tag"].endswith("-ws"):
                self.assertEqual(
                    outbound["streamSettings"]["tlsSettings"]["alpn"], ["http/1.1"]
                )

    def test_xhttp_legs_use_stream_one_and_the_xhttp_path(self):
        legs = [o for o in build() if "-xhttp-" in o["tag"]]
        self.assertEqual(len(legs), 4)
        for outbound in legs:
            stream = outbound["streamSettings"]
            self.assertEqual(stream["network"], "xhttp")
            self.assertEqual(stream["xhttpSettings"]["mode"], "stream-one")
            self.assertEqual(stream["xhttpSettings"]["path"], "/OTHER/xhttp")

    def test_ws_legs_use_the_ws_path(self):
        legs = [o for o in build() if o["tag"].endswith("-ws")]
        self.assertEqual(len(legs), 2)
        for outbound in legs:
            self.assertEqual(outbound["streamSettings"]["network"], "ws")
            self.assertEqual(
                outbound["streamSettings"]["wsSettings"]["path"], "/SECRET/vless"
            )

    def test_each_leg_addresses_its_own_node_by_name(self):
        # Not cloud.beerloga.su: round-robin DNS would make the probe measure
        # a different node than the tag claims.
        for outbound in build()[:6]:
            expected = (
                "cloud1.beerloga.su"
                if outbound["tag"].startswith("cloud1")
                else "cloud2.beerloga.su"
            )
            vnext = outbound["settings"]["vnext"][0]
            self.assertEqual(vnext["address"], expected)
            self.assertEqual(vnext["port"], 443)
            self.assertEqual(vnext["users"][0]["id"], UUID)
            self.assertEqual(vnext["users"][0]["encryption"], "none")
            self.assertEqual(
                outbound["streamSettings"]["tlsSettings"]["serverName"], expected
            )

    def test_missing_ws_path_drops_only_the_ws_legs(self):
        tags = [o["tag"] for o in build(ws=None)]
        self.assertEqual(
            tags,
            [
                "cloud1-xhttp-h3",
                "cloud2-xhttp-h3",
                "cloud1-xhttp-h2",
                "cloud2-xhttp-h2",
                "direct",
                "block",
            ],
        )

    def test_missing_xhttp_path_drops_only_the_xhttp_legs(self):
        tags = [o["tag"] for o in build(xhttp=None)]
        self.assertEqual(tags, ["cloud1-ws", "cloud2-ws", "direct", "block"])


class BuildConfigTest(unittest.TestCase):
    def setUp(self):
        self.user = make_user()
        self.doc = gen.build_config(self.user, NODES)

    def test_remarks_name_the_user(self):
        self.assertIn("alice", self.doc["remarks"])

    def test_socks_inbound_comes_first_on_10808(self):
        # iOS/macOS builds of Happ expect socks before any other inbound.
        inbounds = self.doc["inbounds"]
        self.assertEqual(inbounds[0]["tag"], "socks-in")
        self.assertEqual(inbounds[0]["protocol"], "socks")
        self.assertEqual(inbounds[0]["port"], 10808)
        self.assertTrue(inbounds[0]["settings"]["udp"])
        self.assertEqual(inbounds[1]["tag"], "http-in")
        self.assertEqual(inbounds[1]["port"], 10809)

    def test_socks_inbound_sniffs_so_domains_survive_the_tun(self):
        sniffing = self.doc["inbounds"][0]["sniffing"]
        self.assertTrue(sniffing["enabled"])
        self.assertEqual(sniffing["destOverride"], ["http", "tls", "quic"])
        self.assertFalse(sniffing["routeOnly"])

    def test_routing_sends_private_direct_then_everything_to_the_balancer(self):
        rules = self.doc["routing"]["rules"]
        self.assertEqual(rules[0]["outboundTag"], "direct")
        self.assertIn("192.168.0.0/16", rules[0]["ip"])
        self.assertIn("fc00::/7", rules[0]["ip"])
        self.assertEqual(rules[1]["network"], "tcp,udp")
        self.assertEqual(rules[1]["balancerTag"], gen.BALANCER_TAG)

    def test_domain_strategy_is_asis_so_resolution_happens_server_side(self):
        self.assertEqual(self.doc["routing"]["domainStrategy"], "AsIs")

    def test_no_geoip_or_geosite_tokens_anywhere(self):
        # Happ may hand the core trimmed geo databases in JSON mode.
        blob = json.dumps(self.doc)
        self.assertNotIn("geoip:", blob)
        self.assertNotIn("geosite:", blob)

    def test_balancer_selector_matches_every_proxy_leg(self):
        balancer = self.doc["routing"]["balancers"][0]
        self.assertEqual(balancer["tag"], gen.BALANCER_TAG)
        self.assertEqual(balancer["strategy"], {"type": "leastPing"})
        proxy_tags = [o["tag"] for o in self.doc["outbounds"]][:6]
        for tag in proxy_tags:
            self.assertTrue(
                any(tag.startswith(prefix) for prefix in balancer["selector"]),
                f"{tag} not covered by selector {balancer['selector']}",
            )

    def test_observatory_probes_the_same_legs(self):
        observatory = self.doc["burstObservatory"]
        self.assertEqual(
            observatory["subjectSelector"],
            self.doc["routing"]["balancers"][0]["selector"],
        )
        ping = observatory["pingConfig"]
        self.assertEqual(ping["destination"], gen.PING_DESTINATION)
        self.assertEqual(ping["interval"], "30s")
        self.assertEqual(ping["timeout"], "5s")
        self.assertEqual(ping["sampling"], 3)

    def test_no_dns_block(self):
        # AsIs means nothing to resolve locally; Happ owns the tunnel DNS.
        self.assertNotIn("dns", self.doc)

    def test_uses_the_users_own_paths(self):
        user = make_user(name="nodeuser", xhttp="/OWN/xhttp", ws="/OWN/vless")
        doc = gen.build_config(user, NODES)
        paths = {
            o["streamSettings"].get("xhttpSettings", o["streamSettings"].get("wsSettings", {}))["path"]
            for o in doc["outbounds"][:6]
        }
        self.assertEqual(paths, {"/OWN/xhttp", "/OWN/vless"})


class GoldenJsonTest(unittest.TestCase):
    """Every `.json` subscription in the golden corpus is reproducible.

    Broader than BuildConfigTest's hand-built user: it walks the synthetic
    config, pins the subscription for each user that has one, and asserts a user
    without a VLESS subscription gets none. Serialisation matches the generator
    exactly — a one-element array, indent=2, ensure_ascii=False, trailing
    newline. NODES equals the pair used to snapshot the corpus.
    """

    def test_matches_the_golden_corpus(self):
        import artifacts
        import config_model

        server = config_model.load(GOLDEN_CONFIG)
        for user in server.users:
            path = GOLDEN_DIR / f"{user.filename}.json"
            with self.subTest(user=user.filename):
                if not artifacts.has_subscription(user):
                    self.assertFalse(path.exists())
                    continue
                document = gen.build_config(user, NODES)
                actual = json.dumps([document], indent=2, ensure_ascii=False) + "\n"
                self.assertEqual(actual, path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
