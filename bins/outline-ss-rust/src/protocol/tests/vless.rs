use super::*;

const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

// Wire-format coverage for parse_request/build_request_header lives in
// `outline-wire`; these tests cover the server-side account entity.

#[test]
fn reject_unknown_uuid() {
    let known = VlessUser::new(UUID.to_owned(), std::sync::Arc::from("test"), None, None).unwrap();
    let unknown = parse_uuid("650e8400-e29b-41d4-a716-446655440000").unwrap();
    assert!(find_user(&[known], &unknown).is_none());
}

#[test]
fn finds_user_by_uuid_and_keeps_label() {
    let user =
        VlessUser::new(UUID.to_owned(), std::sync::Arc::from("alice-mom"), Some(7), None).unwrap();
    let id = *user.id_bytes();
    let found = find_user(std::slice::from_ref(&user), &id).unwrap();
    assert_eq!(found.label(), "alice-mom");
    assert_eq!(found.fwmark(), Some(7));
}

#[test]
fn rejects_malformed_uuid() {
    let err = VlessUser::new("zz".to_owned(), std::sync::Arc::from("bad"), None, None).unwrap_err();
    assert_eq!(err, VlessError::InvalidUuid);
}

#[test]
fn with_effective_label_relabels_by_source_ip() {
    let cidrs = ["10.0.0.0/8".to_string()];
    let table = outline_net::IpAliasTable::build([("mobile", cidrs.as_slice())]).unwrap();
    let user = VlessUser::new(
        UUID.to_owned(),
        std::sync::Arc::from("base"),
        None,
        Some(std::sync::Arc::new(table)),
    )
    .unwrap();
    // In-subnet relabels the instance; downstream reads label()/label_arc().
    let relabeled = user.clone().with_effective_label(Some("10.1.2.3".parse().unwrap()));
    assert_eq!(relabeled.label(), "mobile");
    // The UUID identity is preserved — authentication still matches.
    assert_eq!(relabeled.id_bytes(), user.id_bytes());
    // Out-of-subnet keeps the base label.
    let other = user
        .clone()
        .with_effective_label(Some("203.0.113.1".parse().unwrap()));
    assert_eq!(other.label(), "base");
    // Absent peer keeps the base label.
    assert_eq!(user.with_effective_label(None).label(), "base");
}
