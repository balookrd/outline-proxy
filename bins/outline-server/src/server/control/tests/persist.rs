use super::*;
use crate::config::{CipherKind, OneOrManyCidr, UserEntry};

fn entry(id: &str, password: &str) -> UserEntry {
    UserEntry {
        id: id.to_owned(),
        password: Some(password.to_owned()),
        fwmark: None,
        method: None,
        vless_id: None,
        enabled: None,
        aliases: None,
    }
}

fn upsert(user: UserEntry) -> UserMutation {
    UserMutation::Upsert(Box::new(user))
}

/// A config shaped like a deployed one: several users, and real sections both
/// before AND after the `[[users]]` run. The sections after it are the ones a
/// whole-list rewrite is most likely to disturb.
const FLEET_CONFIG: &str = r#"# outline-server config.
[server]
listen = "0.0.0.0:443"

[websocket]
ws_path_ss = "/ss"

[shadowsocks]
method = "chacha20-ietf-poly1305"

# Users start here.
[[users]]
# The owner's laptop.
id = "alice"
password = "p-alice"   # rotate quarterly
fwmark = 1001

[[users]]
id = "mmv-mac"
password = "p-mac"

[[users]]
id = "beerloga"
password = "p-beerloga"
enabled = false

[control]
listen = "127.0.0.1:9190"
token = "control-secret"

[dashboard]
enabled = true

[cluster]
enabled = false

[tuning]
udp_nat_max_entries = 65536
"#;

/// Every id present in the patched document, in file order.
fn ids(doc: &str) -> Vec<String> {
    let parsed: toml_edit::DocumentMut = doc.parse().expect("patched config must parse");
    let users = parsed.get("users").expect("users key");
    if let Some(tables) = users.as_array_of_tables() {
        return tables
            .iter()
            .map(|t| t["id"].as_str().expect("id").to_owned())
            .collect();
    }
    users
        .as_array()
        .expect("users is neither array-of-tables nor array")
        .iter()
        .map(|v| {
            v.as_inline_table().expect("inline table")["id"]
                .as_str()
                .expect("id")
                .to_owned()
        })
        .collect()
}

/// One user's key in the patched document, as rendered TOML.
fn user_key(doc: &str, id: &str, key: &str) -> Option<String> {
    let parsed: toml_edit::DocumentMut = doc.parse().expect("patched config must parse");
    parsed
        .get("users")?
        .as_array_of_tables()?
        .iter()
        .find(|t| t.get("id").and_then(|i| i.as_str()) == Some(id))?
        .get(key)
        .map(|item| item.to_string().trim().to_owned())
}

/// The regression this module exists for: adding one user must not delete the
/// others, and must not touch any other section.
#[test]
fn creating_a_user_keeps_every_other_user_and_section() {
    let out = patch_toml(FLEET_CONFIG, &upsert(entry("cloud3", "p-cloud3"))).expect("patch");

    assert_eq!(
        ids(&out),
        vec!["alice", "mmv-mac", "beerloga", "cloud3"],
        "existing users lost or reordered:\n{out}"
    );
    for section in [
        "[server]",
        "[websocket]",
        "[shadowsocks]",
        "[control]",
        "[dashboard]",
        "[cluster]",
        "[tuning]",
    ] {
        assert!(out.contains(section), "section {section} lost:\n{out}");
    }
    assert!(out.contains(r#"token = "control-secret""#), "control token lost:\n{out}");
    assert!(out.contains("udp_nat_max_entries = 65536"), "tuning value lost:\n{out}");
    assert!(out.contains(r#"password = "p-alice""#), "alice's password changed:\n{out}");
}

/// The file keeps the shape an admin edits by hand: `[[users]]` tables (not one
/// inline `users = [...]` line), in place, with their comments.
#[test]
fn patching_preserves_table_layout_and_comments() {
    let out = patch_toml(FLEET_CONFIG, &upsert(entry("cloud3", "p-cloud3"))).expect("patch");

    assert_eq!(
        out.matches("[[users]]").count(),
        4,
        "users no longer stored as `[[users]]` tables:\n{out}"
    );
    assert!(!out.contains("users = ["), "users collapsed into an inline array:\n{out}");
    assert!(out.contains("# outline-server config."), "header comment lost:\n{out}");
    assert!(out.contains("# Users start here."), "section comment lost:\n{out}");
    assert!(out.contains("# The owner's laptop."), "in-block comment lost:\n{out}");
    assert!(out.contains("# rotate quarterly"), "inline value comment lost:\n{out}");
    // The new user lands inside the `[[users]]` run, not after `[tuning]`.
    let new_user = out.find(r#"id = "cloud3""#).expect("new user present");
    assert!(
        new_user < out.find("[control]").expect("control section"),
        "new user escaped the users run:\n{out}"
    );
}

/// An update rewrites only the keys that changed, in place.
#[test]
fn updating_a_user_touches_only_that_entry() {
    let mut updated = entry("alice", "p-alice-rotated");
    updated.fwmark = Some(1001);
    let out = patch_toml(FLEET_CONFIG, &upsert(updated)).expect("patch");

    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"], "user set changed:\n{out}");
    assert!(out.contains(r#"password = "p-alice-rotated""#), "new password missing:\n{out}");
    assert!(!out.contains(r#"password = "p-alice""#), "old password survived:\n{out}");
    assert!(
        out.contains("# rotate quarterly"),
        "comment beside the rotated value lost:\n{out}"
    );
    assert!(out.contains(r#"password = "p-mac""#), "other user's password changed:\n{out}");
}

/// Keys the user no longer has are dropped rather than left stale.
#[test]
fn updating_a_user_drops_keys_it_no_longer_has() {
    // `beerloga` is `enabled = false` on disk; unblocking clears the key.
    let out = patch_toml(FLEET_CONFIG, &upsert(entry("beerloga", "p-beerloga"))).expect("patch");

    assert!(
        user_key(&out, "beerloga", "enabled").is_none(),
        "stale `enabled` key survived:\n{out}"
    );
    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"], "user set changed:\n{out}");
    // `[cluster] enabled = false` is a different key in a different section.
    assert!(out.contains("[cluster]\nenabled = false"), "cluster section disturbed:\n{out}");
}

#[test]
fn blocking_a_user_writes_the_enabled_key() {
    let mut blocked = entry("alice", "p-alice");
    blocked.fwmark = Some(1001);
    blocked.enabled = Some(false);
    let out = patch_toml(FLEET_CONFIG, &upsert(blocked)).expect("patch");

    assert!(out.contains("enabled = false"), "block not written:\n{out}");
    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"], "user set changed:\n{out}");
}

#[test]
fn deleting_a_user_removes_only_that_entry() {
    let out = patch_toml(FLEET_CONFIG, &UserMutation::Remove("mmv-mac".to_owned())).expect("patch");

    assert_eq!(ids(&out), vec!["alice", "beerloga"], "wrong users removed:\n{out}");
    assert!(out.contains(r#"token = "control-secret""#), "control section lost:\n{out}");
    assert!(!out.contains("p-mac"), "deleted user's password survived:\n{out}");
}

/// Deleting a user the file never had is a no-op, not an error.
#[test]
fn deleting_an_absent_user_leaves_the_file_byte_identical() {
    let out = patch_toml(FLEET_CONFIG, &UserMutation::Remove("nobody".to_owned())).expect("patch");
    assert_eq!(out, FLEET_CONFIG);
}

/// Re-writing a user with exactly the state already on disk changes nothing —
/// `persist_user_mutation` uses this to skip the write entirely.
#[test]
fn no_op_upsert_leaves_the_file_byte_identical() {
    let mut same = entry("alice", "p-alice");
    same.fwmark = Some(1001);
    let out = patch_toml(FLEET_CONFIG, &upsert(same)).expect("patch");
    assert_eq!(out, FLEET_CONFIG);
}

/// A `[users.aliases]` sub-table stays a sub-table instead of collapsing into
/// the inline form serde emits.
#[test]
fn aliases_keep_their_sub_table_form() {
    let original = r#"[[users]]
id = "alice"
password = "p-alice"

[users.aliases]
alice-mobile = "10.0.0.0/8"

[tuning]
udp_nat_max_entries = 65536
"#;
    let mut updated = entry("alice", "p-alice");
    updated.aliases = Some(
        [
            ("alice-mobile".to_owned(), OneOrManyCidr::One("10.0.0.0/8".to_owned())),
            ("alice-office".to_owned(), OneOrManyCidr::One("192.0.2.0/24".to_owned())),
        ]
        .into_iter()
        .collect(),
    );

    let out = patch_toml(original, &upsert(updated)).expect("patch");

    assert!(out.contains("[users.aliases]"), "aliases collapsed to inline:\n{out}");
    assert!(out.contains(r#"alice-office = "192.0.2.0/24""#), "new alias missing:\n{out}");
    assert!(out.contains("[tuning]"), "later section lost:\n{out}");
    // The patched document still loads as the real config schema.
    let parsed: toml_edit::DocumentMut = out.parse().expect("parse round-trip");
    assert!(parsed.get("users").is_some());
}

/// A config left in the inline shape by older builds is patched in that same
/// shape — one entry at a time, without reformatting the rest.
#[test]
fn inline_users_array_is_patched_in_place() {
    let original = r#"users = [{ id = "alice", password = "p-alice" }, { id = "bob", password = "p-bob" }]

[tuning]
udp_nat_max_entries = 65536
"#;

    let out = patch_toml(original, &upsert(entry("cloud3", "p-cloud3"))).expect("patch");
    assert_eq!(ids(&out), vec!["alice", "bob", "cloud3"], "inline patch lost users:\n{out}");
    assert!(out.contains("[tuning]"), "later section lost:\n{out}");

    let out = patch_toml(original, &UserMutation::Remove("alice".to_owned())).expect("patch");
    assert_eq!(ids(&out), vec!["bob"], "inline remove hit the wrong entry:\n{out}");
}

/// A config with no `[[users]]` yet grows one, without disturbing what is there.
#[test]
fn first_user_is_appended_to_a_config_without_any() {
    let original = "[server]\nlisten = \"0.0.0.0:443\"\n";
    let out = patch_toml(original, &upsert(entry("alice", "p-alice"))).expect("patch");

    assert_eq!(ids(&out), vec!["alice"]);
    assert!(out.contains("[[users]]"), "not written as a table:\n{out}");
    assert!(out.contains(r#"listen = "0.0.0.0:443""#), "server section lost:\n{out}");
}

/// A `users` key of some other type is a config we do not understand; refuse
/// rather than replace it.
#[test]
fn foreign_users_key_is_refused() {
    let err =
        patch_toml("users = \"nope\"\n", &upsert(entry("alice", "p"))).expect_err("must refuse");
    assert!(format!("{err:#}").contains("refusing to rewrite"), "unexpected error: {err:#}");
}

#[test]
fn method_change_round_trips() {
    let mut updated = entry("mmv-mac", "p-mac");
    updated.method = Some(CipherKind::Aes256Gcm);
    let out = patch_toml(FLEET_CONFIG, &upsert(updated)).expect("patch");
    assert!(out.contains(r#"method = "aes-256-gcm""#), "method not written:\n{out}");
    assert_eq!(ids(&out), vec!["alice", "mmv-mac", "beerloga"]);
}

#[test]
fn patch_toml_config_updates_cluster_and_preserves_comments() {
    let patch = ServerConfigPatch {
        cluster: FieldPatch::Set(Some(ClusterConfigPatch {
            enabled: FieldPatch::Set(Some(true)),
            shard_id: FieldPatch::Set(Some(2)),
            cluster_psk: FieldPatch::Set(Some(
                "k5O0r1S0t3U4v5W6x7Y8z9A0b1C2d3E4f5G6h7I8j9K=".to_string(),
            )),
            mesh_listen: FieldPatch::Set(Some("[::]:9443".to_string())),
            mesh_relay_budget_ms: FieldPatch::Set(Some(5000)),
            peers: FieldPatch::Set(Some(vec![
                ClusterPeerPatch { shard: 0, addr: "node0:9443".to_string() },
                ClusterPeerPatch { shard: 1, addr: "node1:9443".to_string() },
            ])),
        })),
        session_resumption: FieldPatch::Set(Some(SessionResumptionPatch {
            enabled: FieldPatch::Set(Some(true)),
            orphan_ttl_tcp_secs: FieldPatch::Set(Some(300)),
            orphan_ttl_udp_secs: FieldPatch::Set(Some(120)),
            ..Default::default()
        })),
        tuning_profile: FieldPatch::Set(Some("medium".to_string())),
        ..Default::default()
    };

    let out = patch_toml_config(FLEET_CONFIG, &patch).expect("patch config");
    assert!(out.contains("enabled = true"), "cluster.enabled missing:\n{out}");
    assert!(out.contains("shard_id = 2"), "shard_id missing:\n{out}");
    assert!(
        out.contains(r#"cluster_psk = "k5O0r1S0t3U4v5W6x7Y8z9A0b1C2d3E4f5G6h7I8j9K=""#),
        "psk missing:\n{out}"
    );
    assert!(out.contains(r#"mesh_listen = "[::]:9443""#), "mesh_listen missing:\n{out}");
    assert!(out.contains("mesh_relay_budget_ms = 5000"), "relay budget missing:\n{out}");
    assert!(out.contains(r#"tuning_profile = "medium""#), "tuning profile missing:\n{out}");
    assert!(out.contains("[session_resumption]"), "session_resumption missing:\n{out}");
    // Verify comments and users are intact
    assert!(out.contains("# Users start here."));
    assert!(out.contains("# The owner's laptop."));
    assert!(out.contains("alice"));
    assert!(out.contains("beerloga"));
}

#[test]
fn patch_toml_config_updates_server_listeners_and_outbound() {
    let patch = ServerConfigPatch {
        server: FieldPatch::Set(Some(ServerListenerPatch {
            listen: FieldPatch::Set(Some("0.0.0.0:8443".to_string())),
            cert_path: FieldPatch::Set(Some("/etc/ssl/cert.pem".to_string())),
            key_path: FieldPatch::Set(Some("/etc/ssl/key.pem".to_string())),
            h3_listen: FieldPatch::Set(Some("0.0.0.0:8443".to_string())),
            ..Default::default()
        })),
        outbound: FieldPatch::Set(Some(OutboundPatch {
            prefer_ipv4: FieldPatch::Set(Some(true)),
            ipv6_prefix: FieldPatch::Set(Some("2001:db8::/64".to_string())),
            ..Default::default()
        })),
        ..Default::default()
    };

    let original = "[server]\nlisten = \"0.0.0.0:443\"\n";
    let out = patch_toml_config(original, &patch).expect("patch server");
    assert!(out.contains(r#"listen = "0.0.0.0:8443""#), "listen updated:\n{out}");
    assert!(out.contains(r#"cert_path = "/etc/ssl/cert.pem""#), "cert_path updated:\n{out}");
    assert!(out.contains("prefer_ipv4 = true"), "prefer_ipv4 updated:\n{out}");
    assert!(out.contains(r#"ipv6_prefix = "2001:db8::/64""#), "ipv6_prefix updated:\n{out}");
    assert!(out.contains("[server.h3]"), "h3 subtable created:\n{out}");
}

#[test]
fn patch_toml_config_updates_padding_http_fallback_and_extended_fields() {
    let patch = ServerConfigPatch {
        server: FieldPatch::Set(Some(ServerListenerPatch {
            h3_initial_mtu: FieldPatch::Set(Some(1350)),
            h3_mtu_first_probe: FieldPatch::Set(Some(1452)),
            ..Default::default()
        })),
        outbound: FieldPatch::Set(Some(OutboundPatch {
            ipv6_prefix_interface: FieldPatch::Set(Some("eth0".to_string())),
            ipv6_refresh_secs: FieldPatch::Set(Some(120)),
            ..Default::default()
        })),
        padding: FieldPatch::Set(Some(PaddingConfigPatch {
            min_bytes: FieldPatch::Set(Some(16)),
            max_bytes: FieldPatch::Set(Some(512)),
            cover: FieldPatch::Set(Some(true)),
            throttle_detect_enabled: FieldPatch::Set(Some(true)),
            throttle_ratio_percent: FieldPatch::Set(Some(250)),
            ..Default::default()
        })),
        http_fallback: FieldPatch::Set(Some(HttpFallbackPatch {
            backend: FieldPatch::Set(Some("127.0.0.1:8080".to_string())),
            proxy_protocol: FieldPatch::Set(Some("v2".to_string())),
            backend_proto: FieldPatch::Set(Some("h1".to_string())),
            apply_to_h1: FieldPatch::Set(Some(true)),
            apply_to_h3: FieldPatch::Set(Some(false)),
            ..Default::default()
        })),
        tuning_profile: FieldPatch::Set(Some("medium".to_string())),
        ..Default::default()
    };

    let original = "[server]\nlisten = \"0.0.0.0:443\"\n";
    let out = patch_toml_config(original, &patch).expect("patch config");
    assert!(out.contains("[server.h3]"), "h3 subtable created:\n{out}");
    assert!(out.contains("initial_mtu = 1350"), "initial_mtu set:\n{out}");
    assert!(out.contains("mtu_first_probe = 1452"), "mtu_first_probe set:\n{out}");
    assert!(
        out.contains(r#"ipv6_prefix_interface = "eth0""#),
        "ipv6_prefix_interface set:\n{out}"
    );
    assert!(out.contains("ipv6_refresh_secs = 120"), "ipv6_refresh_secs set:\n{out}");
    assert!(out.contains("[padding]"), "padding table created:\n{out}");
    assert!(out.contains("min_bytes = 16"), "min_bytes set:\n{out}");
    assert!(out.contains("max_bytes = 512"), "max_bytes set:\n{out}");
    assert!(out.contains("cover = true"), "cover set:\n{out}");
    assert!(
        out.contains("throttle_detect_enabled = true"),
        "throttle_detect_enabled set:\n{out}"
    );
    assert!(
        out.contains("throttle_ratio_percent = 250"),
        "throttle_ratio_percent set:\n{out}"
    );
    assert!(out.contains("[http_fallback]"), "http_fallback table created:\n{out}");
    assert!(out.contains(r#"backend = "127.0.0.1:8080""#), "backend set:\n{out}");
    assert!(out.contains(r#"proxy_protocol = "v2""#), "proxy_protocol set:\n{out}");
    assert!(out.contains(r#"backend_proto = "h1""#), "backend_proto set:\n{out}");
    assert!(out.contains(r#"tuning_profile = "medium""#), "tuning_profile set:\n{out}");
}

#[test]
fn patch_toml_config_updates_sni_fallback_and_backends() {
    let patch = ServerConfigPatch {
        sni_fallback: FieldPatch::Set(Some(SniFallbackPatch {
            match_sni: FieldPatch::Set(Some(vec!["*.fleet.example".to_string()])),
            allow_no_sni: FieldPatch::Set(Some(false)),
            max_client_hello_bytes: FieldPatch::Set(Some(4096)),
            backends: FieldPatch::Set(Some(vec![SniBackendPatch {
                backend: "127.0.0.1:11443".to_string(),
                proxy_protocol: Some("v1".to_string()),
                match_sni: None,
            }])),
        })),
        http_fallback: FieldPatch::Set(Some(HttpFallbackPatch {
            backend: FieldPatch::Set(Some("http://127.0.0.1:8080".to_string())),
            proxy_protocol: FieldPatch::Set(Some("v2".to_string())),
            apply_to_h3: FieldPatch::Set(Some(true)),
            ..Default::default()
        })),
        ..Default::default()
    };

    let original = "[server]\nlisten = \"0.0.0.0:443\"\n";
    let out = patch_toml_config(original, &patch).expect("patch config with sni_fallback");

    assert!(out.contains("[sni_fallback]"), "sni_fallback table created:\n{out}");
    assert!(out.contains(r#"match_sni = ["*.fleet.example"]"#), "match_sni set:\n{out}");
    assert!(out.contains("allow_no_sni = false"), "allow_no_sni set:\n{out}");
    assert!(out.contains("[[sni_fallback.backends]]"), "backends table created:\n{out}");
    assert!(out.contains(r#"backend = "127.0.0.1:11443""#), "backend set:\n{out}");
    assert!(out.contains(r#"proxy_protocol = "v1""#), "proxy_protocol set:\n{out}");
    assert!(out.contains("[http_fallback]"), "http_fallback table created:\n{out}");
    assert!(out.contains(r#"backend = "http://127.0.0.1:8080""#), "http backend set:\n{out}");
    assert!(out.contains("apply_to_h3 = true"), "apply_to_h3 set:\n{out}");

    // Assert that the generated TOML is valid FileConfig and resolves SniFallbackConfig
    let file: crate::config::FileConfig = toml::from_str(&out).expect("parse generated TOML");
    let sf_sec = file.sni_fallback.expect("sni_fallback section present");
    assert_eq!(sf_sec.allow_no_sni, Some(false));
    assert_eq!(sf_sec.match_sni.as_deref(), Some(&["*.fleet.example".to_string()][..]));
    let bes = sf_sec.backends.expect("backends present");
    assert_eq!(bes.len(), 1);
    assert_eq!(bes[0].backend, "127.0.0.1:11443");
    assert_eq!(bes[0].proxy_protocol.as_deref(), Some("v1"));
}

#[test]
fn patch_toml_config_updates_endpoint_padding() {
    let original = r#"
[server]
listen = "0.0.0.0:443"

[[endpoint]]
path = "/ss-ws"
kind = "ws_ss"
padded = false

[[endpoint]]
path = "/ss-xh"
kind = "xhttp_ss"
padding = true
"#;

    let patch = ServerConfigPatch {
        endpoints: FieldPatch::Set(Some(vec![
            EndpointPatch {
                path: "/ss-ws".to_string(),
                kind: None,
                padded: true,
            },
            EndpointPatch {
                path: "/ss-xh".to_string(),
                kind: None,
                padded: false,
            },
        ])),
        ..Default::default()
    };

    let out = patch_toml_config(original, &patch).expect("patch config endpoints");
    assert!(out.contains("path = \"/ss-ws\""), "contains /ss-ws");
    assert!(out.contains("path = \"/ss-xh\""), "contains /ss-xh");

    let file: crate::config::FileConfig = toml::from_str(&out).expect("parse generated TOML");
    let endpoints = file.endpoints.expect("endpoints present");
    assert_eq!(endpoints.len(), 2);
    assert_eq!(endpoints[0].path, "/ss-ws");
    assert!(endpoints[0].padded);
    assert_eq!(endpoints[1].path, "/ss-xh");
    assert!(!endpoints[1].padded);
}

#[test]
fn patch_toml_config_supports_endpoint_crud_and_sections_before_users() {
    let original = r#"[server]
listen = "127.0.0.1:443"
cert_path = "cert.pem"
key_path = "key.pem"

[server.h3]
listen = "127.0.0.1:443"

[[users]]
id = "alice"
password = "secret"
"#;

    let patch = ServerConfigPatch {
        shadowsocks: FieldPatch::Set(Some(ShadowsocksPatch {
            method: FieldPatch::Set(Some(CipherKind::Aes256Gcm2022)),
        })),
        http_root: FieldPatch::Set(Some(HttpRootPatch {
            auth: FieldPatch::Set(Some(true)),
            realm: FieldPatch::Set(Some("Relay".to_string())),
        })),
        access_keys: FieldPatch::Set(Some(AccessKeysPatch {
            public_host: FieldPatch::Set(Some("edge.fleet.example".to_string())),
            public_scheme: FieldPatch::Set(Some("wss".to_string())),
            nodes: FieldPatch::Set(Some(vec![
                "relay-a.fleet.example".to_string(),
                "relay-b.fleet.example".to_string(),
            ])),
            ..Default::default()
        })),
        tuning: FieldPatch::Set(Some(TuningPatch {
            dns_cache_max_entries: FieldPatch::Set(Some(4096)),
            ws_data_channel_capacity: FieldPatch::Set(Some(64)),
            ..Default::default()
        })),
        endpoints: FieldPatch::Set(Some(vec![
            EndpointPatch {
                path: "/ws".to_string(),
                kind: Some(EndpointKind::WsSs),
                padded: false,
            },
            EndpointPatch {
                path: "/vless".to_string(),
                kind: Some(EndpointKind::XhttpVless),
                padded: true,
            },
        ])),
        ..Default::default()
    };

    let out = patch_toml_config(original, &patch).expect("patch full sections");
    let parsed = crate::config::parse_and_validate(&out).expect("valid config");
    assert_eq!(parsed.method, CipherKind::Aes256Gcm2022);
    assert!(parsed.http_root_auth);
    assert_eq!(parsed.http_root_realm, "Relay");
    assert_eq!(parsed.endpoints.len(), 2);
    assert_eq!(parsed.endpoints[1].kind, EndpointKind::XhttpVless);
    assert!(parsed.endpoints[1].padded);

    let users_pos = out.find("[[users]]").expect("users section");
    for section in ["[shadowsocks]", "[http_root]", "[access_keys]", "[tuning]", "[[endpoint]]"] {
        let pos = out
            .find(section)
            .unwrap_or_else(|| panic!("missing {section} in:\n{out}"));
        assert!(pos < users_pos, "{section} must be placed before [[users]]:\n{out}");
    }
}

#[test]
fn patch_toml_config_field_patch_null_clears_keys_and_whole_sections() {
    let original = r#"[server]
listen = "127.0.0.1:443"
cert_path = "cert.pem"
key_path = "key.pem"
max_connections_per_ip = 32

[access_keys]
public_host = "edge.fleet.example"
nodes = ["relay-a.fleet.example"]

[http_fallback]
backend = "http://127.0.0.1:8080"

[padding]
min_bytes = 10
max_bytes = 128
cover = true
"#;

    let patch = ServerConfigPatch {
        server: FieldPatch::Set(Some(ServerListenerPatch {
            max_connections_per_ip: FieldPatch::Set(None),
            ..Default::default()
        })),
        access_keys: FieldPatch::Set(Some(AccessKeysPatch {
            nodes: FieldPatch::Set(None),
            ..Default::default()
        })),
        http_fallback: FieldPatch::Set(None),
        padding: FieldPatch::Set(Some(PaddingConfigPatch {
            cover: FieldPatch::Set(None),
            ..Default::default()
        })),
        ..Default::default()
    };

    let out = patch_toml_config(original, &patch).expect("clear via null");
    assert!(!out.contains("max_connections_per_ip"), "field not cleared:\n{out}");
    assert!(!out.contains("nodes"), "access_keys.nodes not cleared:\n{out}");
    assert!(!out.contains("[http_fallback]"), "whole section not removed:\n{out}");
    assert!(!out.contains("cover ="), "padding.cover not cleared:\n{out}");
    assert!(out.contains("min_bytes = 10"), "sibling field lost:\n{out}");
}

#[test]
fn endpoint_section_deserializes_with_padding_alias() {
    let toml_str = r#"
[server]
listen = "0.0.0.0:443"

[[endpoint]]
path = "/test"
kind = "ws_ss"
padding = true
"#;
    let file: crate::config::FileConfig =
        toml::from_str(toml_str).expect("parse with padding alias");
    let ep = &file.endpoints.unwrap()[0];
    assert!(ep.padded);
}

#[test]
fn persist_config_patch_validates_result_and_rejects_invalid_config() {
    let path = std::env::temp_dir()
        .join(format!("outline-ss-persist-patch-{}", std::process::id()))
        .with_extension("toml");
    let original = r#"
[server]
listen = "127.0.0.1:443"
tls_cert_path = "cert.pem"
tls_key_path = "key.pem"

[[users]]
id = "alice"
password = "secret-password"
"#;
    std::fs::write(&path, original).expect("write initial config");

    // Patch that attempts to set an invalid tuning profile name
    let patch = ServerConfigPatch {
        tuning_profile: FieldPatch::Set(Some("invalid-profile-name".to_string())),
        ..Default::default()
    };

    let err =
        persist_config_patch(&path, &patch).expect_err("should reject invalid tuning profile");
    assert!(matches!(err, PersistConfigError::Validation(_)));
    assert!(err.to_string().contains("validation") || err.to_string().contains("failed"));

    // File content remains unchanged
    let after = std::fs::read_to_string(&path).expect("read after failed patch");
    assert_eq!(after, original);
    let _ = std::fs::remove_file(path);
}
