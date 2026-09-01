use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::sniff::{
    reload_domain_suffixes_from_files, should_override_host, spawn_sniff_override_watcher,
};

#[tokio::test]
async fn sniff_override_file_watcher_hot_reloads_on_file_change() {
    let tmp_dir =
        std::env::temp_dir().join(format!("outline-tun-watcher-test-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let inc_file = tmp_dir.join("include.list");
    let exc_file = tmp_dir.join("exclude.list");

    std::fs::write(&inc_file, "initial.com\n").unwrap();
    std::fs::write(&exc_file, "bypass.com\n").unwrap();

    let include_files = vec![inc_file.clone()];
    let inline_include = vec!["inline.org".to_string()];
    let exclude_files = vec![exc_file.clone()];
    let inline_exclude = Vec::new();

    let initial_inc = reload_domain_suffixes_from_files(&include_files, &inline_include).unwrap();
    let initial_exc = reload_domain_suffixes_from_files(&exclude_files, &inline_exclude).unwrap();

    let inc_target = Arc::new(ArcSwap::from_pointee(initial_inc));
    let exc_target = Arc::new(ArcSwap::from_pointee(initial_exc));

    let _guard = spawn_sniff_override_watcher(
        include_files,
        inline_include,
        inc_target.clone(),
        exclude_files,
        inline_exclude,
        exc_target.clone(),
        Duration::from_millis(50),
    );

    // Initial check
    assert!(should_override_host("initial.com", &inc_target.load(), &exc_target.load()));
    assert!(should_override_host("inline.org", &inc_target.load(), &exc_target.load()));
    assert!(!should_override_host("bypass.com", &inc_target.load(), &exc_target.load()));
    assert!(!should_override_host("other.com", &inc_target.load(), &exc_target.load()));

    // Sleep briefly to ensure filesystem mtime difference on some OS filesystems
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Modify include file and exclude file
    std::fs::write(&inc_file, "reloaded.com\n*.wildcard.net\n").unwrap();
    std::fs::write(&exc_file, "newbypass.com\n").unwrap();

    // Poll until updated or timeout
    let mut updated = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let inc = inc_target.load();
        let exc = exc_target.load();
        if should_override_host("reloaded.com", &inc, &exc)
            && should_override_host("sub.wildcard.net", &inc, &exc)
            && !should_override_host("initial.com", &inc, &exc)
            && !should_override_host("newbypass.com", &inc, &exc)
            && should_override_host("inline.org", &inc, &exc)
        {
            updated = true;
            break;
        }
    }

    assert!(updated, "sniff override files failed to hot-reload in time");

    let _ = std::fs::remove_dir_all(tmp_dir);
}
