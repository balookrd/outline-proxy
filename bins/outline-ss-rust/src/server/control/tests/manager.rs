use super::*;
use arc_swap::ArcSwap;

use crate::server::tests::sample_config;

/// Builds a `UserManager` whose only registered route surface is the default
/// tcp/udp paths from `sample_config`.
fn test_manager() -> UserManager {
    manager_for(sample_config("127.0.0.1:0".parse().unwrap()))
}

fn manager_for(config: Config) -> UserManager {
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
        xhttp_ss: Arc::new(std::collections::BTreeMap::new()),
        xhttp_ss_udp: Arc::new(std::collections::BTreeMap::new()),
    }));
    let auth: AuthUsersSnapshot =
        Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(Vec::<UserKey>::new()))));
    let tcp_paths = BTreeSet::from([config.ws_path_tcp.clone()]);
    let udp_paths = BTreeSet::from([config.ws_path_udp.clone()]);
    UserManager::new(
        &config,
        routes,
        auth,
        AllowedRoutePaths {
            tcp: tcp_paths,
            udp: udp_paths,
            vless: BTreeSet::new(),
            xhttp_vless: BTreeSet::new(),
            xhttp_ss: BTreeSet::new(),
            xhttp_ss_udp: BTreeSet::new(),
        },
    )
}

fn vless_only_entry() -> UserEntry {
    UserEntry {
        id: "v".into(),
        password: None,
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: Some("00000000-0000-0000-0000-000000000001".into()),
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

#[test]
fn vless_id_without_any_transport_is_rejected() {
    // A `vless_id` user needs a ws_path_vless or xhttp_path_vless. Raw
    // VLESS-over-QUIC was removed, so no ALPN can satisfy the requirement and
    // the live control API rejects such a user outright.
    let manager = test_manager();
    assert!(
        manager.validate_new(&vless_only_entry()).is_err(),
        "vless_id with no ws/xhttp path must be rejected"
    );
}

fn ss_entry_with_aliases(pairs: &[(&str, &str)]) -> UserEntry {
    let aliases = pairs
        .iter()
        .map(|(name, cidr)| (name.to_string(), crate::config::OneOrManyCidr::One(cidr.to_string())))
        .collect();
    UserEntry {
        id: "ss".into(),
        password: Some("secret".into()),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: Some(aliases),
    }
}

#[test]
fn validate_new_accepts_valid_aliases() {
    let manager = test_manager();
    let entry = ss_entry_with_aliases(&[("mobile", "10.0.0.0/8")]);
    assert!(manager.validate_new(&entry).is_ok());
}

#[test]
fn validate_new_rejects_malformed_alias_cidr() {
    // Control-plane parity with startup `config::validation`.
    let manager = test_manager();
    let entry = ss_entry_with_aliases(&[("mobile", "not-a-cidr")]);
    assert!(manager.validate_new(&entry).is_err());
}

#[test]
fn user_view_exposes_aliases() {
    let entry = ss_entry_with_aliases(&[("mobile", "10.0.0.0/8")]);
    let view = UserView::from(&entry);
    let aliases = view.aliases.expect("aliases should be exposed in the view");
    assert_eq!(aliases["mobile"].as_slice(), &["10.0.0.0/8".to_string()][..]);
}

/// A deployed config: several users, plus sections on both sides of the
/// `[[users]]` run.
const ON_DISK_CONFIG: &str = r#"# Fleet config.
[server]
listen = "0.0.0.0:443"

[[users]]
# The owner's laptop.
id = "alice"
password = "p-alice"

[[users]]
id = "mmv-mac"
password = "p-mac"

[[users]]
id = "beerloga"
password = "p-beerloga"

[control]
listen = "127.0.0.1:9190"
token = "control-secret"

[tuning]
udp_nat_max_entries = 65536
"#;

fn scratch_config(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("outline-ss-control-{}-{}", name, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(&path, ON_DISK_CONFIG).unwrap();
    path
}

/// A manager whose in-memory registry deliberately holds FEWER users than the
/// file: exactly the divergence a whole-list rewrite turns into data loss.
fn manager_over(path: &std::path::Path, held: Vec<UserEntry>) -> UserManager {
    let mut config = sample_config("127.0.0.1:0".parse().unwrap());
    config.config_path = Some(path.to_path_buf());
    config.users = held;
    manager_for(config)
}

fn ss_entry(id: &str, password: &str) -> UserEntry {
    UserEntry {
        id: id.into(),
        password: Some(password.into()),
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        ws_path_ss: None,
        vless_id: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    }
}

fn saved_ids(path: &std::path::Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).expect("config readable");
    let doc: toml_edit::DocumentMut = text.parse().expect("saved config must parse");
    doc.get("users")
        .expect("users key survived")
        .as_array_of_tables()
        .expect("users stayed `[[users]]` tables")
        .iter()
        .map(|t| t["id"].as_str().expect("id").to_owned())
        .collect()
}

/// The data-loss regression. Creating one user must patch that one entry —
/// never re-author the list from the in-memory registry, which would delete
/// every user the runtime happens not to hold.
#[tokio::test]
async fn create_keeps_users_the_runtime_does_not_hold() {
    let path = scratch_config("create");
    let manager = manager_over(&path, vec![ss_entry("alice", "p-alice")]);

    manager.create(ss_entry("cloud3", "p-cloud3")).await.expect("create");

    assert_eq!(
        saved_ids(&path),
        vec!["alice", "mmv-mac", "beerloga", "cloud3"],
        "users on disk were destroyed by a create"
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(r#"token = "control-secret""#), "control section lost:\n{text}");
    assert!(text.contains("udp_nat_max_entries = 65536"), "tuning section lost:\n{text}");
    assert!(text.contains("# The owner's laptop."), "in-block comment lost:\n{text}");
    assert!(text.contains(r#"password = "p-mac""#), "another user's secret lost:\n{text}");
}

#[tokio::test]
async fn update_patches_only_the_named_user() {
    let path = scratch_config("update");
    let manager = manager_over(&path, vec![ss_entry("alice", "p-alice")]);

    let patch = UserPatch {
        password: FieldPatch::Set(Some("p-alice-rotated".into())),
        vless_id: FieldPatch::Missing,
        method: FieldPatch::Missing,
        fwmark: FieldPatch::Missing,
        ws_path_tcp: FieldPatch::Missing,
        ws_path_udp: FieldPatch::Missing,
        ws_path_ss: FieldPatch::Missing,
        ws_path_vless: FieldPatch::Missing,
        xhttp_path_vless: FieldPatch::Missing,
        xhttp_path_tcp: FieldPatch::Missing,
        xhttp_path_udp: FieldPatch::Missing,
        xhttp_path_ss: FieldPatch::Missing,
        aliases: FieldPatch::Missing,
        enabled: None,
    };
    manager.update("alice", patch).await.expect("update");

    assert_eq!(saved_ids(&path), vec!["alice", "mmv-mac", "beerloga"]);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(r#"password = "p-alice-rotated""#), "rotation not saved:\n{text}");
    assert!(
        text.contains(r#"password = "p-beerloga""#),
        "another user's secret lost:\n{text}"
    );
}

#[tokio::test]
async fn delete_removes_only_the_named_user() {
    let path = scratch_config("delete");
    let manager = manager_over(&path, vec![ss_entry("alice", "p-alice")]);

    manager.delete("alice").await.expect("delete");

    assert_eq!(saved_ids(&path), vec!["mmv-mac", "beerloga"], "delete hit the wrong entries");
}

#[tokio::test]
async fn block_and_unblock_patch_only_the_named_user() {
    let path = scratch_config("block");
    let manager = manager_over(&path, vec![ss_entry("alice", "p-alice")]);

    manager.set_enabled("alice", false).await.expect("block");
    assert_eq!(saved_ids(&path), vec!["alice", "mmv-mac", "beerloga"]);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("enabled = false"), "block not saved:\n{text}");
    assert!(text.contains(r#"password = "p-mac""#), "another user's secret lost:\n{text}");

    manager.set_enabled("alice", true).await.expect("unblock");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("enabled = true"), "unblock not saved:\n{text}");
    assert_eq!(saved_ids(&path), vec!["alice", "mmv-mac", "beerloga"]);
}

/// A mutation that cannot be saved must not go live: the API reports the
/// failure, so the data plane and the file have to agree with that answer.
#[tokio::test]
async fn a_failed_write_leaves_the_runtime_untouched() {
    let path = scratch_config("failed-write").with_file_name("config.yaml");
    std::fs::write(&path, ON_DISK_CONFIG).unwrap();
    let manager = manager_over(&path, vec![ss_entry("alice", "p-alice")]);

    // A non-TOML extension is refused by the persist layer.
    manager
        .create(ss_entry("cloud3", "p-cloud3"))
        .await
        .expect_err("unsupported config extension must fail the mutation");

    assert!(manager.get("cloud3").await.is_none(), "rejected user became live anyway");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), ON_DISK_CONFIG, "file was touched");
}
