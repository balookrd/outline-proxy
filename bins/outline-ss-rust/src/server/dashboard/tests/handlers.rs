use super::*;

#[test]
fn encode_path_segment_escapes_slashes_and_spaces() {
    assert_eq!(encode_path_segment("team a/b"), "team%20a%2Fb");
}
