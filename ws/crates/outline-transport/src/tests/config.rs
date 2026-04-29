use super::TransportMode;

#[test]
fn from_str_accepts_http1_and_h1_alias() {
    assert_eq!("http1".parse::<TransportMode>().unwrap(), TransportMode::WsH1);
    assert_eq!("h1".parse::<TransportMode>().unwrap(), TransportMode::WsH1);
    assert_eq!("h2".parse::<TransportMode>().unwrap(), TransportMode::WsH2);
    assert_eq!("h3".parse::<TransportMode>().unwrap(), TransportMode::WsH3);
    assert_eq!("quic".parse::<TransportMode>().unwrap(), TransportMode::Quic);
    assert!("h4".parse::<TransportMode>().is_err());
}

#[test]
fn deserialize_accepts_http1_and_h1_alias() {
    use serde::Deserialize;
    use serde::de::IntoDeserializer;
    use serde::de::value::{Error as DeError, StrDeserializer};

    let canonical = TransportMode::deserialize::<StrDeserializer<DeError>>(
        "http1".into_deserializer(),
    )
    .unwrap();
    let alias =
        TransportMode::deserialize::<StrDeserializer<DeError>>("h1".into_deserializer())
            .unwrap();
    assert_eq!(canonical, TransportMode::WsH1);
    assert_eq!(alias, TransportMode::WsH1);
}
