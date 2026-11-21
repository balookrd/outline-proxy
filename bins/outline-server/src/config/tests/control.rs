use std::path::PathBuf;

use super::ControlConfig;

#[test]
fn debug_output_hides_the_token() {
    let config = ControlConfig {
        listen: "127.0.0.1:9191".parse().unwrap(),
        token: "s3cr3t-control-token".to_owned(),
        access_keys_generator: Some(PathBuf::from("/opt/outline/access-keys/generate_keys.py")),
        access_keys_python: PathBuf::from("python3"),
        access_keys_timeout_secs: 15,
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
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = resolve_control_config(&args, &file).unwrap_err();
    assert!(err.to_string().contains("control.token cannot be empty"));
}

#[test]
fn resolves_access_keys_runner_options_and_validates_bounds() {
    use crate::config::cli::ConfigArgs;
    use crate::config::control::resolve_control_config;
    use crate::config::file::{ControlFileConfig, FileConfig};
    use clap::Parser;

    let args = ConfigArgs::parse_from(["outline-server"]);
    let file = FileConfig {
        control: Some(ControlFileConfig {
            listen: Some("127.0.0.1:9191".parse().unwrap()),
            token: Some("tok".to_owned()),
            access_keys_generator: Some(PathBuf::from("/opt/outline/access-keys/generate_keys.py")),
            access_keys_python: None,
            access_keys_timeout_secs: Some(30),
            ..Default::default()
        }),
        ..Default::default()
    };
    let resolved = resolve_control_config(&args, &file).unwrap().unwrap();
    assert_eq!(
        resolved.access_keys_generator,
        Some(PathBuf::from("/opt/outline/access-keys/generate_keys.py"))
    );
    assert_eq!(resolved.access_keys_python, PathBuf::from("python3"));
    assert_eq!(resolved.access_keys_timeout_secs, 30);

    let bad_timeout = FileConfig {
        control: Some(ControlFileConfig {
            listen: Some("127.0.0.1:9191".parse().unwrap()),
            token: Some("tok".to_owned()),
            access_keys_timeout_secs: Some(0),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(resolve_control_config(&args, &bad_timeout).is_err());

    let empty_gen = FileConfig {
        control: Some(ControlFileConfig {
            listen: Some("127.0.0.1:9191".parse().unwrap()),
            token: Some("tok".to_owned()),
            access_keys_generator: Some(PathBuf::from("   ")),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(resolve_control_config(&args, &empty_gen).is_err());
}
