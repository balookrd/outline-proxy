use super::UserEntry;

#[test]
fn debug_output_hides_the_credentials() {
    let entry = UserEntry {
        id: "alice".to_owned(),
        password: Some("s3cr3t-password".to_owned()),
        fwmark: Some(7),
        method: None,
        vless_id: Some("550e8400-e29b-41d4-a716-446655440000".to_owned()),
        enabled: Some(true),
        aliases: None,
    };
    let rendered = format!("{entry:?}");
    assert!(!rendered.contains("s3cr3t-password"), "password leaked: {rendered}");
    assert!(!rendered.contains("550e8400"), "vless id leaked: {rendered}");
    assert!(rendered.contains("alice"), "id missing: {rendered}");
    assert!(rendered.contains("fwmark: Some(7)"), "fwmark missing: {rendered}");
}

#[test]
fn debug_output_shows_which_credentials_are_absent() {
    let entry = UserEntry {
        id: "bob".to_owned(),
        password: None,
        fwmark: None,
        method: None,
        vless_id: None,
        enabled: None,
        aliases: None,
    };
    let rendered = format!("{entry:?}");
    assert!(rendered.contains("password: None"), "{rendered}");
    assert!(rendered.contains("vless_id: None"), "{rendered}");
}
