use std::{fs, path::PathBuf};

use super::atomic_write;

/// Per-test scratch directory under the system temp dir. Unique per test name
/// and process so parallel test threads don't collide.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("outline-ss-fs-util-{}-{}", name, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `config.toml` holds user passwords and the cluster PSK, so an admin-set
/// restrictive mode must survive every control-plane mutation.
#[cfg(unix)]
#[test]
fn atomic_write_preserves_existing_file_mode() {
    use std::os::unix::fs::PermissionsExt;

    // Two modes so the assertion cannot pass by accident: whatever the ambient
    // umask yields for a fresh temp file, it differs from at least one of them.
    for mode in [0o600u32, 0o640u32] {
        let dir = scratch(&format!("mode-{mode:o}"));
        let path = dir.join("config.toml");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

        atomic_write(&path, b"new").expect("atomic_write");

        let got = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(got, mode, "atomic_write widened mode {mode:o} to {got:o}");
        assert_eq!(fs::read(&path).unwrap(), b"new".as_slice(), "contents not replaced");
    }
}

#[test]
fn atomic_write_creates_target_when_missing() {
    let dir = scratch("missing");
    let path = dir.join("config.toml");
    let _ = fs::remove_file(&path);

    atomic_write(&path, b"fresh").expect("atomic_write on missing target");

    assert_eq!(fs::read(&path).unwrap(), b"fresh".as_slice());
}
