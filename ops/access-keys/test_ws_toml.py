#!/usr/bin/env python3
"""Offline tests for ws_toml.py. Stdlib only; no network, no node access."""

import sys
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ws_toml as gen  # noqa: E402
from config_model import (  # noqa: E402
    AccessKeys,
    Padding,
    ServerConfig,
    SessionResumption,
    User,
)

NODE = "cloud1.beerloga.su"
NODES = ("cloud1.beerloga.su", "cloud2.beerloga.su")
UUID = "11111111-1111-4111-8111-111111111111"

ACCESS_KEYS = AccessKeys(
    public_host="keys.example.com",
    public_scheme="wss",
    url_base="https://keys.example.com/SECRET",
    file_extension=".conf",
    write_dir="/var/www/html/SECRET",
)

ALL_PADDED = Padding(
    enabled=True,
    paths=("/SECRET/xhttp", "/SECRET/vless", "/SECRET/ss", "/SECRET/ssx"),
)


def make_user(
    name="alice",
    password="pw-alice",
    vless_id=UUID,
    ws_path_vless="/SECRET/vless",
    xhttp_path_vless="/SECRET/xhttp",
    ws_path_ss="/SECRET/ss",
    xhttp_path_ss="/SECRET/ssx",
):
    return User(
        name=name,
        filename=name,
        password=password,
        method="chacha20-ietf-poly1305",
        vless_id=vless_id,
        ws_path_tcp="/SECRET/tcp",
        ws_path_udp="/SECRET/udp",
        ws_path_vless=ws_path_vless,
        ws_path_ss=ws_path_ss,
        xhttp_path_vless=xhttp_path_vless,
        xhttp_path_ss=xhttp_path_ss,
    )


def make_server(
    users=(),
    has_h3=True,
    padding=Padding(enabled=False, paths=()),
    resumption=SessionResumption(enabled=False, downlink_buffer_bytes=0),
    cluster_enabled=False,
):
    return ServerConfig(
        access_keys=ACCESS_KEYS,
        users=tuple(users),
        alpn_has_h3=has_h3,
        padding=padding,
        session_resumption=resumption,
        cluster_enabled=cluster_enabled,
    )


class BuildWiresTest(unittest.TestCase):
    def test_full_chain_order(self):
        wires = gen.build_wires(make_user(), NODE, "wss", has_h3=True)
        self.assertEqual(
            [w.path for w in wires],
            ["/SECRET/xhttp", "/SECRET/vless", "/SECRET/ss", "/SECRET/ssx", "/SECRET/xhttp"],
        )
        self.assertIn("type=xhttp&mode=stream-one", wires[0].link)
        self.assertIn("type=ws", wires[1].link)
        self.assertTrue(wires[2].link.startswith("ss://"))
        self.assertIn("type=xhttp&mode=stream-one", wires[3].link)
        self.assertIn("type=xhttp&mode=packet-up", wires[4].link)

    def test_h3_alpn_leads_every_link(self):
        wires = gen.build_wires(make_user(), NODE, "wss", has_h3=True)
        self.assertIn("alpn=h3", wires[0].link)
        self.assertIn("alpn=h3", wires[2].link)

    def test_without_h3_links_lead_with_h2(self):
        wires = gen.build_wires(make_user(), NODE, "wss", has_h3=False)
        for wire in wires:
            self.assertNotIn("alpn=h3", wire.link)
            self.assertIn("alpn=h2", wire.link)

    def test_ss_only_user_keeps_ss_wires(self):
        user = make_user(vless_id=None)
        wires = gen.build_wires(user, NODE, "wss", has_h3=True)
        self.assertEqual([w.path for w in wires], ["/SECRET/ss", "/SECRET/ssx"])
        self.assertTrue(all(w.link.startswith("ss://") for w in wires))

    def test_vless_only_user_keeps_vless_wires(self):
        user = make_user(password=None)
        wires = gen.build_wires(user, NODE, "wss", has_h3=True)
        self.assertEqual(
            [w.path for w in wires], ["/SECRET/xhttp", "/SECRET/vless", "/SECRET/xhttp"]
        )
        self.assertTrue(all(w.link.startswith("vless://") for w in wires))

    def test_missing_paths_shrink_the_chain(self):
        user = make_user(xhttp_path_vless=None, xhttp_path_ss=None)
        wires = gen.build_wires(user, NODE, "wss", has_h3=True)
        self.assertEqual([w.path for w in wires], ["/SECRET/vless", "/SECRET/ss"])

    def test_links_address_the_requested_node(self):
        wires = gen.build_wires(make_user(), "cloud2.beerloga.su", "wss", has_h3=True)
        for wire in wires:
            self.assertIn("@cloud2.beerloga.su:443?", wire.link)

    def test_has_wires_needs_a_credential_and_a_path(self):
        self.assertTrue(gen.has_wires(make_user()))
        self.assertFalse(gen.has_wires(make_user(password=None, vless_id=None)))
        self.assertFalse(
            gen.has_wires(
                make_user(password=None, ws_path_vless=None, xhttp_path_vless=None)
            )
        )


class BuildConfigTest(unittest.TestCase):
    def render(self, user=None, **kwargs):
        user = user or make_user()
        return gen.build_config(user, NODES, make_server(users=[user], **kwargs))

    def parsed(self, **kwargs):
        return tomllib.loads(self.render(**kwargs))

    def test_returns_none_without_wires(self):
        user = make_user(password=None, vless_id=None)
        server = make_server(users=[user])
        self.assertIsNone(gen.build_config(user, NODES, server))

    def test_one_uplink_per_node_named_after_it(self):
        doc = self.parsed()
        uplinks = doc["outline"]["uplinks"]
        self.assertEqual([u["name"] for u in uplinks], ["cloud1", "cloud2"])
        self.assertEqual([u["group"] for u in uplinks], ["main", "main"])
        self.assertEqual([u["weight"] for u in uplinks], [1.0, 1.0])

    def test_primary_is_the_first_wire_rest_are_fallbacks(self):
        doc = self.parsed()
        uplink = doc["outline"]["uplinks"][0]
        self.assertIn("type=xhttp&mode=stream-one", uplink["link"])
        self.assertEqual(len(uplink["fallbacks"]), 4)
        self.assertIn("type=ws", uplink["fallbacks"][0]["link"])
        self.assertTrue(uplink["fallbacks"][1]["link"].startswith("ss://"))

    def test_uplinks_shuffle_wires(self):
        doc = self.parsed()
        self.assertTrue(all(u["shuffle_wires"] for u in doc["outline"]["uplinks"]))

    def test_group_is_active_passive_global_without_auto_failback(self):
        group = self.parsed()["uplink_group"][0]
        self.assertEqual(group["name"], "main")
        self.assertEqual(group["mode"], "active_passive")
        self.assertEqual(group["routing_scope"], "global")
        self.assertEqual(group["reselect_interval"], "6h")
        self.assertTrue(group["tun_wire_dial"])
        self.assertTrue(group["health_weighted_selection"])
        self.assertEqual(group["warm_standby_tcp"], 1)
        self.assertEqual(group["warm_standby_udp"], 1)
        self.assertNotIn("auto_failback", group)

    def test_shared_resume_follows_the_server_cluster(self):
        self.assertFalse(self.parsed()["uplink_group"][0]["shared_resume"])
        self.assertTrue(
            self.parsed(cluster_enabled=True)["uplink_group"][0]["shared_resume"]
        )

    def test_android_tun_profile(self):
        doc = self.parsed()
        self.assertEqual(doc["tun"]["path"], "vpn")
        self.assertEqual(doc["tun"]["mtu"], 1500)
        self.assertTrue(doc["tun"]["tcp"]["sniffing"])
        self.assertTrue(doc["tun"]["tcp"]["carrier_migration"])

    def test_no_host_sections_absent_from_the_android_build(self):
        doc = self.parsed()
        for section in ("socks5", "metrics", "control", "dashboard"):
            self.assertNotIn(section, doc)

    def test_padding_on_when_the_server_pads_every_path(self):
        self.assertTrue(self.parsed(padding=ALL_PADDED)["padding"]["enabled"])

    def test_padding_off_on_partial_coverage(self):
        partial = Padding(enabled=True, paths=("/SECRET/ss",))
        self.assertFalse(self.parsed(padding=partial)["padding"]["enabled"])

    def test_padding_off_when_the_server_does_not_pad(self):
        self.assertFalse(self.parsed()["padding"]["enabled"])

    def test_pads_every_wire_predicate(self):
        user = make_user()
        self.assertTrue(
            gen.pads_every_wire(user, NODES, make_server(users=[user], padding=ALL_PADDED))
        )
        self.assertFalse(
            gen.pads_every_wire(
                user,
                NODES,
                make_server(
                    users=[user], padding=Padding(enabled=True, paths=("/SECRET/ss",))
                ),
            )
        )

    def test_document_is_valid_toml_and_ends_with_a_newline(self):
        text = self.render()
        self.assertTrue(text.endswith("\n"))
        tomllib.loads(text)  # raises on malformed output

    def test_quotes_in_values_are_escaped(self):
        self.assertEqual(gen.quote('a"b\\c'), '"a\\"b\\\\c"')


class FixtureTest(unittest.TestCase):
    """The fixture pins the accepted format; the Rust side proves it loads."""

    def test_matches_the_checked_in_fixtures(self):
        import config_model

        server = config_model.load(HERE / "golden" / "config.toml")
        for name in ("both", "ss-only"):
            user = next(u for u in server.users if u.name == name)
            expected = (HERE / "golden" / "expected-ws" / f"{name}.toml").read_text(
                encoding="utf-8"
            )
            self.assertEqual(gen.build_config(user, NODES, server), expected, name)


class WarningsTest(unittest.TestCase):
    def warn(self, **kwargs):
        user = make_user()
        return gen.config_warnings(user, NODES, make_server(users=[user], **kwargs))

    def test_reports_disabled_resumption(self):
        self.assertIn("session_resumption", " ".join(self.warn()))

    def test_reports_missing_downlink_replay(self):
        text = " ".join(
            self.warn(resumption=SessionResumption(enabled=True, downlink_buffer_bytes=0))
        )
        self.assertIn("downlink_buffer_bytes", text)

    def test_silent_when_every_switch_is_on(self):
        text = " ".join(
            self.warn(
                resumption=SessionResumption(enabled=True, downlink_buffer_bytes=65536),
                cluster_enabled=True,
                padding=ALL_PADDED,
            )
        )
        self.assertEqual(text, "")

    def test_reports_uplink_switch_resets_without_a_cluster(self):
        self.assertIn("cluster", " ".join(self.warn()))

    def test_reports_partial_padding_coverage_with_the_paths(self):
        text = " ".join(self.warn(padding=Padding(enabled=True, paths=("/SECRET/ss",))))
        self.assertIn("padding", text)
        self.assertIn("/SECRET/vless", text)

    def test_silent_about_padding_the_server_does_not_use(self):
        self.assertNotIn("padding", " ".join(self.warn()))

    def test_warnings_never_carry_credentials(self):
        for line in self.warn(padding=Padding(enabled=True, paths=("/SECRET/ss",))):
            self.assertNotIn("pw-alice", line)
            self.assertNotIn(UUID, line)


if __name__ == "__main__":
    unittest.main()
