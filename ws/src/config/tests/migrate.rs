use super::*;
use tempfile::TempDir;

async fn run(source: &str) -> (Option<String>, String, Option<String>) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, source).await.unwrap();
    let migrated = migrate_legacy_config_if_needed(&path, source).await.unwrap();
    let on_disk = fs::read_to_string(&path).await.unwrap();
    let backup = fs::read_to_string(backup_path(&path)).await.ok();
    (migrated, on_disk, backup)
}

#[tokio::test]
async fn migrates_inline_uplink_fields_into_synthetic_default() {
    let src = "tcp_ws_url = \"wss://example.com/tcp\"\n\
               method = \"chacha20-ietf-poly1305\"\n\
               password = \"secret\"\n\n\
               [probe]\n\
               interval_secs = 30\n";
    let (migrated, on_disk, backup) = run(src).await;
    let out = migrated.expect("migration should run");
    assert_eq!(out, on_disk);
    assert_eq!(backup.as_deref(), Some(src));
    assert!(out.contains("[outline.probe]"));
    assert!(out.contains("[[outline.uplinks]]"));
    assert!(out.contains("name = \"default\""));
    assert!(out.contains("tcp_ws_url = \"wss://example.com/tcp\""));
    assert!(!out.contains("\n[probe]\n"));
}

#[tokio::test]
async fn migrates_top_level_uplinks_array() {
    let src = "[[uplinks]]\n\
               name = \"primary\"\n\
               tcp_ws_url = \"wss://a/tcp\"\n\
               method = \"chacha20-ietf-poly1305\"\n\
               password = \"s\"\n\
               weight = 1.0\n";
    let (_, on_disk, _) = run(src).await;
    assert!(on_disk.contains("[[outline.uplinks]]"));
    assert!(!on_disk.contains("\n[[uplinks]]"));
}

#[tokio::test]
async fn no_op_when_already_grouped() {
    let src = "[outline.probe]\n\
               interval_secs = 30\n\n\
               [[outline.uplinks]]\n\
               name = \"primary\"\n\
               tcp_ws_url = \"wss://a/tcp\"\n\
               method = \"chacha20-ietf-poly1305\"\n\
               password = \"s\"\n\
               weight = 1.0\n";
    let (migrated, on_disk, backup) = run(src).await;
    assert!(migrated.is_none(), "no migration expected");
    assert_eq!(on_disk, src);
    assert!(backup.is_none(), "no backup should be created");
}

#[cfg(unix)]
#[tokio::test]
async fn readonly_dir_falls_back_to_in_memory_migration() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    let src = "tcp_ws_url = \"wss://example.com/tcp\"\n\
               method = \"chacha20-ietf-poly1305\"\n\
               password = \"secret\"\n";
    fs::write(&path, src).await.unwrap();

    // Drop write permission on the containing directory so write() fails
    // with EACCES — the closest portable stand-in for EROFS.
    let orig = fs::metadata(dir.path()).await.unwrap().permissions();
    fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555))
        .await
        .unwrap();

    let result = migrate_legacy_config_if_needed(&path, src).await;

    // Restore perms so TempDir cleanup works.
    fs::set_permissions(dir.path(), orig).await.unwrap();

    let migrated = result.expect("readonly fs should not fail startup");
    let out = migrated.expect("in-memory migration should have produced text");
    assert!(out.contains("[[outline.uplinks]]"));
    // File on disk is unchanged and no backup was written.
    assert_eq!(fs::read_to_string(&path).await.unwrap(), src);
    assert!(fs::read_to_string(backup_path(&path)).await.is_err());
}

#[tokio::test]
async fn migrate_config_file_rewrites_and_reports_change() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("config.toml");
    let src = "tcp_ws_url = \"wss://example.com/tcp\"\n\
               method = \"chacha20-ietf-poly1305\"\n\
               password = \"secret\"\n";
    fs::write(&path, src).await.unwrap();

    let changed = migrate_config_file(&path).await.unwrap();
    assert!(changed);
    assert!(
        fs::read_to_string(&path)
            .await
            .unwrap()
            .contains("[[outline.uplinks]]")
    );

    // Second invocation: no change, no error.
    let changed = migrate_config_file(&path).await.unwrap();
    assert!(!changed);
}

#[tokio::test]
async fn explicit_outline_fields_win_over_top_level() {
    let src = "password = \"legacy\"\n\
               [outline]\n\
               password = \"explicit\"\n\
               tcp_ws_url = \"wss://a/tcp\"\n\
               method = \"chacha20-ietf-poly1305\"\n";
    let (_, on_disk, _) = run(src).await;
    assert!(on_disk.contains("password = \"explicit\""));
    assert!(!on_disk.contains("password = \"legacy\""));
}
