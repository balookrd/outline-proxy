use super::ControlConfig;

#[test]
fn debug_output_hides_the_token() {
    let config = ControlConfig {
        listen: "127.0.0.1:9191".parse().unwrap(),
        token: "s3cr3t-control-token".to_owned(),
    };
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("s3cr3t-control-token"), "token leaked: {rendered}");
    assert!(rendered.contains("127.0.0.1:9191"), "listen address missing: {rendered}");
}
