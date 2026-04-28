use super::*;

#[tokio::test]
async fn write_atomic_creates_file_with_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    write_atomic(&path, b"hello").await.unwrap();
    let got = tokio::fs::read(&path).await.unwrap();
    assert_eq!(got, b"hello");
}

#[tokio::test]
async fn write_atomic_leaves_no_tmp_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    write_atomic(&path, b"x").await.unwrap();
    let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
    let mut names = Vec::new();
    while let Some(e) = entries.next_entry().await.unwrap() {
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    assert_eq!(names, vec!["state.toml"]);
}

#[cfg(unix)]
#[tokio::test]
async fn write_atomic_sets_0600_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    write_atomic(&path, b"x").await.unwrap();
    let mode = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[tokio::test]
async fn write_atomic_overwrites_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    tokio::fs::write(&path, b"old").await.unwrap();
    write_atomic(&path, b"new").await.unwrap();
    let got = tokio::fs::read(&path).await.unwrap();
    assert_eq!(got, b"new");
}

// ── StateStore tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn state_store_in_memory_update_reflected_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    let store = StateStore::load_or_default(path).await;
    store.update_active("g1", Some(Some("u1".into())), None, None).await;
    let gs = store.group_state("g1").await;
    assert_eq!(gs.global_active, Some("u1".to_string()));
    assert_eq!(gs.tcp_active, None);
    assert_eq!(gs.udp_active, None);
}

#[tokio::test]
async fn state_store_none_field_leaves_existing_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    let store = StateStore::load_or_default(path).await;
    store.update_active("g", Some(Some("a".into())), Some(Some("b".into())), None).await;
    // Pass None for global — must not touch the existing value.
    store.update_active("g", None, Some(Some("c".into())), None).await;
    let gs = store.group_state("g").await;
    assert_eq!(gs.global_active, Some("a".to_string()));
    assert_eq!(gs.tcp_active, Some("c".to_string()));
}

#[tokio::test]
async fn state_store_clear_field_with_some_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    let store = StateStore::load_or_default(path).await;
    store.update_active("g", Some(Some("x".into())), None, None).await;
    // Some(None) must clear the field.
    store.update_active("g", Some(None), None, None).await;
    assert_eq!(store.group_state("g").await.global_active, None);
}

#[tokio::test]
async fn state_store_missing_group_returns_blank_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    let store = StateStore::load_or_default(path).await;
    let gs = store.group_state("no_such_group").await;
    assert_eq!(gs.global_active, None);
    assert_eq!(gs.tcp_active, None);
    assert_eq!(gs.udp_active, None);
}

#[tokio::test]
async fn state_store_persists_to_disk_and_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    {
        let store = StateStore::load_or_default(path.clone()).await;
        store
            .update_active(
                "grp",
                Some(Some("uplink1".into())),
                None,
                Some(Some("uplink2".into())),
            )
            .await;
        store.clone().spawn_writer();
        // Wait for the 200 ms debounce + slack.
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let reloaded = StateStore::load_or_default(path).await;
    let gs = reloaded.group_state("grp").await;
    assert_eq!(gs.global_active, Some("uplink1".to_string()));
    assert_eq!(gs.udp_active, Some("uplink2".to_string()));
}

#[tokio::test]
async fn state_store_corrupt_file_starts_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    tokio::fs::write(&path, b"this is not valid toml!!!@@@").await.unwrap();
    let store = StateStore::load_or_default(path).await;
    let gs = store.group_state("any").await;
    assert_eq!(gs.global_active, None);
}

#[tokio::test]
async fn state_store_empty_file_starts_fresh() {
    // First-run scenario: the state file exists (e.g. pre-created by
    // systemd-tmpfiles or an install script) but is empty. Must parse
    // as an empty PersistedState without warnings, not fail or crash.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.toml");
    tokio::fs::write(&path, b"").await.unwrap();
    let store = StateStore::load_or_default(path).await;
    let gs = store.group_state("any").await;
    assert_eq!(gs.global_active, None);
    assert_eq!(gs.tcp_active, None);
    assert_eq!(gs.udp_active, None);
}

#[tokio::test]
async fn state_store_missing_file_starts_fresh() {
    // No state file at all (clean install). Must not error; subsequent
    // update + flush should create the file atomically.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("never-existed.toml");
    assert!(!path.exists());
    let store = StateStore::load_or_default(path.clone()).await;
    let gs = store.group_state("any").await;
    assert_eq!(gs.global_active, None);
}
