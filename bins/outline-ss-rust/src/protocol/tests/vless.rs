use super::*;

const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

// Wire-format coverage for parse_request/build_request_header lives in
// `outline-wire`; these tests cover the server-side account entity.

#[test]
fn reject_unknown_uuid() {
    let known = VlessUser::new(UUID.to_owned(), std::sync::Arc::from("test"), None).unwrap();
    let unknown = parse_uuid("650e8400-e29b-41d4-a716-446655440000").unwrap();
    assert!(find_user(&[known], &unknown).is_none());
}

#[test]
fn finds_user_by_uuid_and_keeps_label() {
    let user = VlessUser::new(UUID.to_owned(), std::sync::Arc::from("alice-mom"), Some(7)).unwrap();
    let id = *user.id_bytes();
    let found = find_user(std::slice::from_ref(&user), &id).unwrap();
    assert_eq!(found.label(), "alice-mom");
    assert_eq!(found.fwmark(), Some(7));
}

#[test]
fn rejects_malformed_uuid() {
    let err = VlessUser::new("zz".to_owned(), std::sync::Arc::from("bad"), None).unwrap_err();
    assert_eq!(err, VlessError::InvalidUuid);
}
