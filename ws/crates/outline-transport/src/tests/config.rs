use super::WsTransportMode;

#[test]
fn from_str_accepts_http1_and_h1_alias() {
    assert_eq!("http1".parse::<WsTransportMode>().unwrap(), WsTransportMode::Http1);
    assert_eq!("h1".parse::<WsTransportMode>().unwrap(), WsTransportMode::Http1);
    assert_eq!("h2".parse::<WsTransportMode>().unwrap(), WsTransportMode::H2);
    assert_eq!("h3".parse::<WsTransportMode>().unwrap(), WsTransportMode::H3);
    assert_eq!("quic".parse::<WsTransportMode>().unwrap(), WsTransportMode::Quic);
    assert!("h4".parse::<WsTransportMode>().is_err());
}

#[test]
fn deserialize_accepts_http1_and_h1_alias() {
    use serde::Deserialize;
    use serde::de::IntoDeserializer;
    use serde::de::value::{Error as DeError, StrDeserializer};

    let canonical = WsTransportMode::deserialize::<StrDeserializer<DeError>>(
        "http1".into_deserializer(),
    )
    .unwrap();
    let alias =
        WsTransportMode::deserialize::<StrDeserializer<DeError>>("h1".into_deserializer())
            .unwrap();
    assert_eq!(canonical, WsTransportMode::Http1);
    assert_eq!(alias, WsTransportMode::Http1);
}
