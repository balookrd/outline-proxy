#!/usr/bin/env python3
"""Offline tests for ws_toml.py. Stdlib only; no network, no node access."""

import sys
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ws_toml as gen  # noqa: E402
from config_model import (  # noqa: E402
    AccessKeys,
    Endpoint,
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

# The four chain-eligible carriers, in no particular order (build_wires imposes
# its own). Split SS legs are omitted: they never join the wire chain.
FULL_EPS = (
    Endpoint("/SECRET/xhttp", "xhttp_vless", False),
    Endpoint("/SECRET/vless", "ws_vless", False),
    Endpoint("/SECRET/ss", "ws_ss", False),
    Endpoint("/SECRET/ssx", "xhttp_ss", False),
)
ALL_PADDED_EPS = tuple(replace(e, padded=True) for e in FULL_EPS)
SS_PADDED_EPS = tuple(replace(e, padded=e.kind in ("ws_ss", "xhttp_ss")) for e in FULL_EPS)
WS_ONLY_EPS = (
    Endpoint("/SECRET/vless", "ws_vless", False),
    Endpoint("/SECRET/ss", "ws_ss", False),
)
SS_ONLY_EPS = (
    Endpoint("/SECRET/ss", "ws_ss", False),
    Endpoint("/SECRET/ssx", "xhttp_ss", False),
)


def make_user(name="alice", password="pw-alice", vless_id=UUID, method="chacha20-ietf-poly1305"):
    return User(name=name, filename=name, password=password, method=method, vless_id=vless_id)


def make_server(
    users=(),
    has_h3=True,
    endpoints=FULL_EPS,
    resumption=SessionResumption(enabled=False, downlink_buffer_bytes=0),
    cluster_enabled=False,
):
    return ServerConfig(
        access_keys=ACCESS_KEYS,
        users=tuple(users),
        alpn_has_h3=has_h3,
        endpoints=tuple(endpoints),
        session_resumption=resumption,
        cluster_enabled=cluster_enabled,
    )


class BuildWiresTest(unittest.TestCase):
    def test_full_chain_order(self):
        wires = gen.build_wires(make_user(), NODE, make_server(has_h3=True))
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
        wires = gen.build_wires(make_user(), NODE, make_server(has_h3=True))
        self.assertIn("alpn=h3", wires[0].link)
        self.assertIn("alpn=h3", wires[2].link)

    def test_without_h3_links_lead_with_h2(self):
        wires = gen.build_wires(make_user(), NODE, make_server(has_h3=False))
        for wire in wires:
            self.assertNotIn("alpn=h3", wire.link)
            self.assertIn("alpn=h2", wire.link)

    def test_ss_only_user_keeps_ss_wires(self):
        wires = gen.build_wires(make_user(vless_id=None), NODE, make_server())
        self.assertEqual([w.path for w in wires], ["/SECRET/ss", "/SECRET/ssx"])
        self.assertTrue(all(w.link.startswith("ss://") for w in wires))

    def test_vless_only_user_keeps_vless_wires(self):
        wires = gen.build_wires(make_user(password=None), NODE, make_server())
        self.assertEqual(
            [w.path for w in wires], ["/SECRET/xhttp", "/SECRET/vless", "/SECRET/xhttp"]
        )
        self.assertTrue(all(w.link.startswith("vless://") for w in wires))

    def test_missing_endpoints_shrink_the_chain(self):
        # No xhttp_vless / xhttp_ss on the server → those carriers drop out.
        wires = gen.build_wires(make_user(), NODE, make_server(endpoints=WS_ONLY_EPS))
        self.assertEqual([w.path for w in wires], ["/SECRET/vless", "/SECRET/ss"])

    def test_each_wire_carries_its_endpoint_padded_flag(self):
        wires = gen.build_wires(make_user(), NODE, make_server(endpoints=SS_PADDED_EPS))
        padded = {w.path: w.padded for w in wires}
        self.assertTrue(padded["/SECRET/ss"])
        self.assertTrue(padded["/SECRET/ssx"])
        self.assertFalse(padded["/SECRET/vless"])
        self.assertFalse(padded["/SECRET/xhttp"])

    def test_links_address_the_requested_node(self):
        wires = gen.build_wires(make_user(), "cloud2.beerloga.su", make_server())
        for wire in wires:
            self.assertIn("@cloud2.beerloga.su:443?", wire.link)

    def test_shuffle_timer_is_stable_in_range_and_varies_by_identity(self):
        alice = make_user(name="alice")
        # Idempotent: a re-run must not churn the client's config.
        self.assertEqual(gen.shuffle_timer(alice, NODE), gen.shuffle_timer(alice, NODE))
        # Always a whole-minute value inside the closed range.
        self.assertRegex(gen.shuffle_timer(alice, NODE), r"^\d+m$")
        self.assertTrue(30 <= int(gen.shuffle_timer(alice, NODE)[:-1]) <= 60)
        # Not a constant: identity moves the period. The two group nodes each
        # carry their own cadence rather than rerolling in lockstep.
        self.assertNotEqual(
            gen.shuffle_timer(alice, NODES[0]), gen.shuffle_timer(alice, NODES[1])
        )

    def test_has_wires_needs_a_credential_and_an_endpoint(self):
        self.assertTrue(gen.has_wires(make_user(), make_server()))
        # No credential at all.
        self.assertFalse(gen.has_wires(make_user(password=None, vless_id=None), make_server()))
        # A VLESS credential but the server offers no VLESS endpoint.
        self.assertFalse(
            gen.has_wires(make_user(password=None), make_server(endpoints=SS_ONLY_EPS))
        )


class BuildConfigTest(unittest.TestCase):
    def render(self, user=None, **kwargs):
        user = user or make_user()
        return gen.build_config(user, NODES, make_server(users=[user], **kwargs))

    def parsed(self, **kwargs):
        return tomllib.loads(self.render(**kwargs))

    def test_returns_none_without_wires(self):
        user = make_user(password=None, vless_id=None)
        self.assertIsNone(gen.build_config(user, NODES, make_server(users=[user])))

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

    def test_shuffle_on_rerolls_the_active_wire_on_a_per_uplink_timer(self):
        # With the chain shuffled, also reroll the *active* wire on a timer so a
        # steady flow never settles on one carrier shape. The period is a stable
        # per-uplink pick in [30, 60] minutes, not a constant.
        doc = self.parsed()
        uplinks = doc["outline"]["uplinks"]
        self.assertTrue(all(u["shuffle_wires"] for u in uplinks))
        for u in uplinks:
            timer = u["shuffle_timer"]
            self.assertRegex(timer, r"^\d+m$", timer)
            self.assertTrue(30 <= int(timer[:-1]) <= 60, timer)

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

    def test_padding_on_when_any_wire_is_padded(self):
        self.assertTrue(self.parsed(endpoints=ALL_PADDED_EPS)["padding"]["enabled"])

    def test_padding_off_when_no_wire_is_padded(self):
        self.assertFalse(self.parsed()["padding"]["enabled"])

    def test_padded_chain_keeps_only_the_padded_wires(self):
        # ss_ss/xhttp_ss are padded, the VLESS carriers are not: padding turns on
        # and the plain VLESS wires are dropped so the chain is one padding class.
        doc = self.parsed(endpoints=SS_PADDED_EPS)
        self.assertTrue(doc["padding"]["enabled"])
        uplink = doc["outline"]["uplinks"][0]
        self.assertTrue(uplink["link"].startswith("ss://"))
        self.assertEqual(len(uplink["fallbacks"]), 1)
        self.assertTrue(uplink["fallbacks"][0]["link"].startswith("ss://"))

    def test_padding_enabled_predicate(self):
        user = make_user()
        self.assertTrue(gen.padding_enabled(user, make_server(endpoints=ALL_PADDED_EPS)))
        self.assertTrue(gen.padding_enabled(user, make_server(endpoints=SS_PADDED_EPS)))
        self.assertFalse(gen.padding_enabled(user, make_server(endpoints=FULL_EPS)))

    def test_document_is_valid_toml_and_ends_with_a_newline(self):
        text = self.render()
        self.assertTrue(text.endswith("\n"))
        tomllib.loads(text)  # raises on malformed output

    def test_quotes_in_values_are_escaped(self):
        self.assertEqual(gen.quote('a"b\\c'), '"a\\"b\\\\c"')


class FixtureTest(unittest.TestCase):
    """The expected-ws fixtures pin the accepted format; Rust proves they load.

    `both.toml` here is loaded through the real ws-rust config loader by
    `generated_android_config_fixture_loads` — its `deny_unknown_fields` schema
    is the thing this fixture guards against silent drift.
    """

    def test_matches_the_checked_in_fixtures(self):
        import config_model

        server = config_model.load(HERE / "golden" / "config.toml")
        for name in ("both", "ss-only"):
            user = next(u for u in server.users if u.name == name)
            expected = (HERE / "golden" / "expected-ws" / f"{name}.toml").read_text(
                encoding="utf-8"
            )
            self.assertEqual(gen.build_config(user, NODES, server), expected, name)


class GoldenTomlTest(unittest.TestCase):
    """Every `.toml` in the golden corpus is reproducible from build_config.

    Broader than FixtureTest: it walks the synthetic config and pins the ws-rust
    config for every user, and asserts a credential-less user gets none. NODES
    equals xray_json.DEFAULT_NODES, the pair the generator used to snapshot the
    corpus, so the comparison is byte-for-byte.
    """

    def test_matches_the_golden_corpus(self):
        import config_model

        server = config_model.load(HERE / "golden" / "config.toml")
        expected_dir = HERE / "golden" / "expected"
        for user in server.users:
            doc = gen.build_config(user, NODES, server)
            path = expected_dir / f"{user.filename}.toml"
            with self.subTest(user=user.filename):
                if doc is None:
                    self.assertFalse(path.exists())
                else:
                    self.assertEqual(doc, path.read_text(encoding="utf-8"))


class WarningsTest(unittest.TestCase):
    def warn(self, **kwargs):
        user = make_user()
        return gen.config_warnings(user, make_server(users=[user], **kwargs))

    def test_reports_disabled_resumption(self):
        self.assertIn("session_resumption", " ".join(self.warn()))

    def test_reports_missing_downlink_replay(self):
        text = " ".join(
            self.warn(resumption=SessionResumption(enabled=True, downlink_buffer_bytes=0))
        )
        self.assertIn("downlink_buffer_bytes", text)

    def test_silent_when_every_switch_is_on_and_the_whole_chain_pads(self):
        text = " ".join(
            self.warn(
                resumption=SessionResumption(enabled=True, downlink_buffer_bytes=65536),
                cluster_enabled=True,
                endpoints=ALL_PADDED_EPS,
            )
        )
        self.assertEqual(text, "")

    def test_reports_uplink_switch_resets_without_a_cluster(self):
        self.assertIn("cluster", " ".join(self.warn()))

    def test_reports_dropped_plain_fallbacks_when_padding_is_on(self):
        text = " ".join(self.warn(endpoints=SS_PADDED_EPS))
        self.assertIn("padding", text)
        # The dropped plain VLESS carriers are named by path.
        self.assertIn("/SECRET/vless", text)
        self.assertIn("/SECRET/xhttp", text)

    def test_silent_about_padding_when_nothing_is_padded(self):
        self.assertNotIn("padding", " ".join(self.warn()))

    def test_silent_about_padding_when_the_whole_chain_pads(self):
        # Padding on, but no plain wire was dropped — nothing to warn about.
        self.assertNotIn("padding", " ".join(self.warn(endpoints=ALL_PADDED_EPS)))

    def test_warnings_never_carry_credentials(self):
        for line in self.warn(endpoints=SS_PADDED_EPS):
            self.assertNotIn("pw-alice", line)
            self.assertNotIn(UUID, line)


if __name__ == "__main__":
    unittest.main()
