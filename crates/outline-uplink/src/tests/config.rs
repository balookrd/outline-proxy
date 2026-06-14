//! Parsing / Display contract for [`UplinkTransport`], including the
//! deprecated `ws` / `websocket` aliases kept for back-compat after the
//! canonical transport name was changed from `ws` to `ss`.

use crate::config::UplinkTransport;

#[test]
fn from_str_maps_canonical_and_aliases_to_ss() {
    // `ss` is canonical; `shadowsocks` is an equal alias; `ws` / `websocket`
    // are deprecated aliases retained until a future release.
    for s in ["ss", "shadowsocks", "ws", "websocket"] {
        assert_eq!(
            s.parse::<UplinkTransport>().unwrap(),
            UplinkTransport::Ss,
            "{s} should parse to Ss"
        );
    }
    assert_eq!("vless".parse::<UplinkTransport>().unwrap(), UplinkTransport::Vless);
    assert!("nope".parse::<UplinkTransport>().is_err());
}

#[test]
fn display_emits_canonical_names() {
    assert_eq!(UplinkTransport::Ss.to_string(), "ss");
    assert_eq!(UplinkTransport::Vless.to_string(), "vless");
}

#[test]
fn deserialises_canonical_and_aliases_to_ss() {
    #[derive(serde::Deserialize)]
    struct Wrap {
        transport: UplinkTransport,
    }
    for s in ["ss", "shadowsocks", "ws", "websocket"] {
        let w: Wrap = toml::from_str(&format!("transport = \"{s}\"")).unwrap();
        assert_eq!(w.transport, UplinkTransport::Ss, "{s} should deserialise to Ss");
    }
    let w: Wrap = toml::from_str("transport = \"vless\"").unwrap();
    assert_eq!(w.transport, UplinkTransport::Vless);
}
