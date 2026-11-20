use super::*;

/// A user id lands in the control URL's path. Without encoding, an id like
/// `x/../../control/apply` would reach a different endpoint entirely.
#[test]
fn path_segment_encoding_blocks_traversal() {
    assert_eq!(encode_path_segment("plain-id_1"), "plain-id_1");
    assert_eq!(encode_path_segment("a/b"), "a%2Fb");
    assert_eq!(encode_path_segment("x?y=1"), "x%3Fy%3D1");
    assert_eq!(encode_path_segment("../../etc"), "%2E%2E%2F%2E%2E%2Fetc");
    assert_eq!(encode_path_segment(".."), "%2E%2E");
    assert_eq!(encode_path_segment("."), "%2E");
}

#[test]
fn user_id_validation_rejects_dot_segments_and_slashes() {
    assert!(!is_valid_user_id(""));
    assert!(!is_valid_user_id("   "));
    assert!(!is_valid_user_id("."));
    assert!(!is_valid_user_id(".."));
    assert!(!is_valid_user_id("foo/bar"));
    assert!(!is_valid_user_id("foo\\bar"));
    assert!(is_valid_user_id("valid-user-123"));
    assert!(is_valid_user_id("user.name"));
}
