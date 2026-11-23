use crate::updater::{
    UpdateCheckResult, UpdateInfo, UpdateManager, WEEKLY_CHECK_INTERVAL_SECS, is_periodic_check_due,
};

fn sample_update() -> UpdateInfo {
    UpdateInfo {
        label: "v26.11.3".to_string(),
        asset_name: "OutlineProxy-v26.11.3-Windows-x86_64.zip".to_string(),
        download_url: "https://example.invalid/win.zip".to_string(),
        checksums_url: Some("https://example.invalid/SHA256SUMS.txt".to_string()),
        notes: "Fixes".to_string(),
        commit: "abcdef12".to_string(),
    }
}

#[test]
fn test_is_periodic_check_due() {
    let base = 1_700_000_000u64;
    let week = WEEKLY_CHECK_INTERVAL_SECS;

    assert!(is_periodic_check_due(None, base, week));
    assert!(is_periodic_check_due(Some(0), base, week));
    assert!(is_periodic_check_due(Some(base + 100), base, week));

    assert!(!is_periodic_check_due(Some(base), base, week));
    assert!(!is_periodic_check_due(Some(base), base + week - 1, week));
    assert!(is_periodic_check_due(Some(base), base + week, week));
    assert!(is_periodic_check_due(Some(base), base + week + 60, week));
}

#[test]
fn test_update_manager_check_transitions() {
    let mgr = UpdateManager::new();
    assert!(!mgr.state().checking);
    assert!(!mgr.state().installing);
    assert_eq!(mgr.state().available, None);

    // Interactive check blocks concurrent check and sets checking status.
    assert!(mgr.begin_check(true));
    assert!(!mgr.begin_check(false));
    assert_eq!(mgr.state().status.as_deref(), Some("проверка обновлений…"));

    let upd = sample_update();
    let st = mgr.finish_check(&Ok(UpdateCheckResult::Available(upd.clone())), false);
    assert!(!st.checking);
    assert_eq!(st.available.as_ref(), Some(&upd));
    assert_eq!(st.status.as_deref(), Some("доступно v26.11.3 — нажмите"));

    // Interactive UpToDate clears available and sets transient status.
    assert!(mgr.begin_check(true));
    let st = mgr.finish_check(&Ok(UpdateCheckResult::UpToDate), true);
    assert_eq!(st.available, None);
    assert_eq!(st.status.as_deref(), Some("актуальная версия"));

    // Background error leaves existing status untouched.
    assert!(mgr.begin_check(false));
    let st = mgr.finish_check(&Err("network error".to_string()), false);
    assert!(!st.checking);
    assert_eq!(st.status.as_deref(), Some("актуальная версия"));

    // Interactive error reports failure.
    assert!(mgr.begin_check(true));
    let st = mgr.finish_check(&Err("network error".to_string()), true);
    assert_eq!(st.status.as_deref(), Some("ошибка проверки"));
}

#[test]
fn test_update_manager_install_lifecycle() {
    let mgr = UpdateManager::new();
    assert!(mgr.begin_install());
    assert!(!mgr.begin_install());
    assert!(!mgr.begin_check(true));
    assert!(mgr.state().installing);

    let st = mgr.finish_install_failed();
    assert!(!st.installing);
    assert!(mgr.begin_check(false));
}
