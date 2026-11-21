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

#[test]
fn empty_literal_control_token_is_rejected() {
    use crate::config::cli::ConfigArgs;
    use crate::config::control::resolve_control_config;
    use crate::config::file::{ControlFileConfig, FileConfig};
    use clap::Parser;

    let args = ConfigArgs::parse_from(["outline-server"]);
    let file = FileConfig {
        control: Some(ControlFileConfig {
            listen: Some("127.0.0.1:9191".parse().unwrap()),
            token: Some("   ".to_owned()),
            token_file: None,
        }),
        ..Default::default()
    };
    let err = resolve_control_config(&args, &file).unwrap_err();
    assert!(err.to_string().contains("control.token cannot be empty"));
}
