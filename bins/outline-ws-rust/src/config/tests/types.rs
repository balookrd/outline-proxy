use super::ControlConfig;

#[test]
fn control_config_debug_output_hides_the_token() {
    let config = ControlConfig {
        listen: "127.0.0.1:9191".parse().unwrap(),
        token: "s3cr3t-control-token".to_owned(),
        config_path: Some("/etc/outline/config.toml".into()),
    };
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("s3cr3t-control-token"), "token leaked: {rendered}");
    assert!(rendered.contains("/etc/outline/config.toml"), "config path missing: {rendered}");
}
