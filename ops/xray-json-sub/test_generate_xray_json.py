#!/usr/bin/env python3
"""Offline tests for generate_xray_json.py. Stdlib only; no network, no node access."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_xray_json as gen  # noqa: E402

# Trimmed to the keys the generator reads. Values are fake.
CONFIG_TOML = """
[server]
listen = "[::]:443"

[websocket]
ws_path_tcp = "/SECRET/tcp"
ws_path_vless = "/SECRET/vless"
xhttp_path_vless = "/OTHER/xhttp"

[[users]]
id = "alice"
password = "pw1"
vless_id = "11111111-1111-4111-8111-111111111111"

[[users]]
id = "bob"
password = "pw2"
vless_id = "22222222-2222-4222-8222-222222222222"

[[users]]
id = "legacy-ss-only"
password = "pw3"
"""


def write_config(tmpdir, text=CONFIG_TOML):
    path = Path(tmpdir) / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


class LoadServerConfigTest(unittest.TestCase):
    def test_reads_paths_and_vless_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = gen.load_server_config(write_config(tmp))
        self.assertEqual(server.xhttp_path, "/OTHER/xhttp")
        self.assertEqual(server.ws_path, "/SECRET/vless")
        self.assertEqual([u.name for u in server.users], ["alice", "bob"])
        self.assertEqual(
            server.users[0].vless_id, "11111111-1111-4111-8111-111111111111"
        )

    def test_skips_user_without_vless_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = gen.load_server_config(write_config(tmp))
        self.assertNotIn("legacy-ss-only", [u.name for u in server.users])

    def test_rejects_config_without_vless_paths(self):
        stripped = '[websocket]\nws_path_tcp = "/SECRET/tcp"\n'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                gen.load_server_config(write_config(tmp, stripped))


NODES = ("cloud1.beerloga.su", "cloud2.beerloga.su")
UUID = "11111111-1111-4111-8111-111111111111"


def build():
    return gen.build_outbounds(UUID, "/OTHER/xhttp", "/SECRET/vless", NODES)


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


class BuildConfigTest(unittest.TestCase):
    def setUp(self):
        self.server = gen.ServerConfig(
            xhttp_path="/OTHER/xhttp",
            ws_path="/SECRET/vless",
            users=(gen.User(name="alice", vless_id=UUID),),
        )
        self.doc = gen.build_config(self.server.users[0], self.server, NODES)

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


class WriteAndMainTest(unittest.TestCase):
    def test_document_on_disk_is_a_single_element_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "keys"
            user = gen.User(name="alice", vless_id=UUID)
            gen.write_subscription(out, user, {"remarks": "alice cloud-balancer"})
            payload = json.loads((out / "alice.json").read_text(encoding="utf-8"))
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["remarks"], "alice cloud-balancer")

    def test_written_file_is_world_readable_and_leaves_no_temp_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "keys"
            gen.write_subscription(out, gen.User(name="alice", vless_id=UUID), {})
            target = out / "alice.json"
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o644)
            self.assertEqual([p.name for p in out.iterdir()], ["alice.json"])

    def test_main_writes_one_file_per_vless_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = write_config(tmp)
            out = Path(tmp) / "keys"
            rc = gen.main(["--config", str(config), "--out-dir", str(out)])
            self.assertEqual(rc, 0)
            self.assertEqual(
                sorted(p.name for p in out.iterdir()), ["alice.json", "bob.json"]
            )
            payload = json.loads((out / "bob.json").read_text(encoding="utf-8"))
        tags = [o["tag"] for o in payload[0]["outbounds"]]
        self.assertEqual(tags[0], "cloud1-xhttp-h3")
        self.assertEqual(tags[-2:], ["direct", "block"])

    def test_main_honours_custom_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = write_config(tmp)
            out = Path(tmp) / "keys"
            gen.main(
                [
                    "--config",
                    str(config),
                    "--out-dir",
                    str(out),
                    "--node",
                    "edge9.example.com",
                ]
            )
            payload = json.loads((out / "alice.json").read_text(encoding="utf-8"))
        tags = [o["tag"] for o in payload[0]["outbounds"]]
        self.assertEqual(
            tags, ["edge9-xhttp-h3", "edge9-xhttp-h2", "edge9-ws", "direct", "block"]
        )

    def test_main_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = write_config(tmp)
            out = Path(tmp) / "keys"
            gen.main(["--config", str(config), "--out-dir", str(out)])
            first = (out / "alice.json").read_text(encoding="utf-8")
            gen.main(["--config", str(config), "--out-dir", str(out)])
            second = (out / "alice.json").read_text(encoding="utf-8")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
