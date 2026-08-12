use std::{fs, path::PathBuf};

use super::atomic_write;

/// Per-test scratch directory under the system temp dir. Unique per test name
/// and process so parallel test threads don't collide.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("outline-ws-fs-util-{}-{}", name, std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `config.toml` holds the SOCKS5/per-user passwords, uplink PSK and the
/// control/dashboard tokens, so an admin-set restrictive mode must survive
/// every control-plane mutation rather than decay to the ambient umask.
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

/// A fresh target has no mode to inherit, so it keeps the private 0600 the temp
/// file was created with. This is the observable proof that the temp window is
/// never world-readable: it is opened 0600 and only relaxed to an *existing*
/// target's (possibly wider) mode afterwards.
#[cfg(unix)]
#[test]
fn atomic_write_creates_target_private_when_missing() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("missing-private");
    let path = dir.join("config.toml");
    let _ = fs::remove_file(&path);

    atomic_write(&path, b"fresh").expect("atomic_write on missing target");

    let got = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        got, 0o600,
        "fresh config is world-readable ({got:o}); temp window was not private"
    );
    assert_eq!(fs::read(&path).unwrap(), b"fresh".as_slice());
}

#[test]
fn atomic_write_creates_target_when_missing() {
    let dir = scratch("missing");
    let path = dir.join("config.toml");
    let _ = fs::remove_file(&path);

    atomic_write(&path, b"fresh").expect("atomic_write on missing target");

    assert_eq!(fs::read(&path).unwrap(), b"fresh".as_slice());
}

/// The service user reads `config.toml` back at startup, so a control-plane
/// write must not hand the file to a different owner.
#[cfg(unix)]
#[test]
fn atomic_write_preserves_owner() {
    use std::os::unix::fs::MetadataExt;

    let dir = scratch("owner");
    let path = dir.join("config.toml");
    fs::write(&path, b"old").unwrap();
    let before = fs::metadata(&path).unwrap();

    atomic_write(&path, b"new").expect("atomic_write");

    let after = fs::metadata(&path).unwrap();
    assert_eq!(after.uid(), before.uid(), "owner uid changed");
    assert_eq!(after.gid(), before.gid(), "owner gid changed");
}

/// The whole point of the temp-file dance: a write that cannot complete leaves
/// the previous config intact rather than a truncated one, and leaves no temp
/// file behind for the next run to trip over.
#[cfg(unix)]
#[test]
fn failed_write_leaves_the_target_intact_and_no_temp_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("readonly");
    let path = dir.join("config.toml");
    fs::write(&path, b"original contents").unwrap();

    // Deny writes to the directory so creating the temp file fails.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let writable_anyway = fs::write(dir.join(".probe"), b"x").is_ok();
    if writable_anyway {
        // Running as root (or on a filesystem that ignores the mode): the
        // failure this test needs cannot be provoked.
        let _ = fs::remove_file(dir.join(".probe"));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }

    let err = atomic_write(&path, b"replacement").expect_err("write into a read-only dir");
    assert!(format!("{err:#}").contains("temp file"), "unexpected error: {err:#}");

    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        b"original contents".as_slice(),
        "target was damaged by a failed write"
    );
    assert!(!dir.join(".config.toml.tmp").exists(), "temp file left behind");
}

/// A successful write cleans up after itself too.
#[test]
fn successful_write_leaves_no_temp_file() {
    let dir = scratch("no-temp");
    let path = dir.join("config.toml");
    fs::write(&path, b"old").unwrap();

    atomic_write(&path, b"new").expect("atomic_write");

    assert!(!dir.join(".config.toml.tmp").exists(), "temp file left behind");
    assert_eq!(fs::read(&path).unwrap(), b"new".as_slice());
}
