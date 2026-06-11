use super::*;

#[test]
fn bearer_token_parsing() {
    let ok = HeaderValue::from_static("Bearer secret");
    assert!(bearer_token_matches(&ok, "secret"));
    let wrong = HeaderValue::from_static("Bearer bad");
    assert!(!bearer_token_matches(&wrong, "secret"));
    let basic = HeaderValue::from_static("Basic secret");
    assert!(!bearer_token_matches(&basic, "secret"));
}
