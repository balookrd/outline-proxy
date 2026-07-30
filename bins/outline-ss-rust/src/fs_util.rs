//! Small filesystem helpers shared across modules.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tracing::warn;

/// Write `bytes` to `path` atomically: first to a sibling `.{name}.tmp`, then
/// rename over `path`. A reader either sees the previous file or the complete
/// new one — never a truncated mix — and a crash mid-write leaves the target
/// untouched.
///
/// The temp file inherits the target's mode and, where the process is allowed
/// to, its owner: `config.toml` is read by the service user at startup, so a
/// mutation that changed either would leave a config the server can no longer
/// load. Contents are fsynced before the rename and the parent directory after
/// it, so the swap also survives a power loss rather than only a process kill.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp: PathBuf = {
        let mut t = path.to_path_buf();
        let fname = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".to_owned());
        t.set_file_name(format!(".{fname}.tmp"));
        t
    };

    let result = write_temp(&tmp, bytes)
        .and_then(|()| carry_target_metadata(path, &tmp))
        .and_then(|()| {
            fs::rename(&tmp, path).with_context(|| {
                format!("failed to rename {} -> {}", tmp.display(), path.display())
            })
        });
    if result.is_err() {
        // The target still holds the previous contents; drop the partial temp
        // file so a later run does not trip over it.
        let _ = fs::remove_file(&tmp);
        return result;
    }
    sync_parent_dir(path);
    Ok(())
}

/// Write the payload to `tmp`, created private (0600) rather than at the
/// ambient umask: it briefly holds the same passwords and cluster PSK as the
/// target, and its mode is only relaxed to the target's afterwards.
fn write_temp(tmp: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(tmp)
        .with_context(|| format!("failed to create temp file {}", tmp.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write temp file {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to fsync temp file {}", tmp.display()))?;
    Ok(())
}

/// Copy the target's mode and owner onto the temp file. The rename replaces
/// the target *including* both, so without this an admin-set `640
/// outline-ss-rust:outline-ss-rust` would decay to the writer's identity at
/// the ambient umask. A missing target (first write) keeps the private mode
/// from [`write_temp`].
#[cfg(unix)]
fn carry_target_metadata(target: &Path, tmp: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let Ok(meta) = fs::metadata(target) else { return Ok(()) };
    fs::set_permissions(tmp, meta.permissions())
        .with_context(|| format!("failed to carry mode over to temp file {}", tmp.display()))?;

    let tmp_meta =
        fs::metadata(tmp).with_context(|| format!("failed to stat temp file {}", tmp.display()))?;
    if tmp_meta.uid() == meta.uid() && tmp_meta.gid() == meta.gid() {
        return Ok(());
    }
    // Only a privileged writer can hand a file to another uid. When we cannot,
    // the file still ends up owned by the process that just wrote it — which is
    // the process that reads it back at startup — so warn instead of failing
    // the mutation.
    if let Err(err) = std::os::unix::fs::chown(tmp, Some(meta.uid()), Some(meta.gid())) {
        warn!(
            path = %target.display(),
            target_uid = meta.uid(),
            target_gid = meta.gid(),
            error = %err,
            "could not preserve config file ownership; it now belongs to this process"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn carry_target_metadata(_target: &Path, _tmp: &Path) -> Result<()> {
    // Elsewhere `Permissions` is only a read-only flag and there is no owner to
    // carry, so there is nothing this could preserve.
    Ok(())
}

/// Fsync the directory so the rename itself is durable. Best-effort: some
/// filesystems reject `fsync` on a directory, and a config that is merely not
/// yet durable is not worth failing a control-plane mutation over.
fn sync_parent_dir(path: &Path) {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Err(err) = fs::File::open(parent).and_then(|dir| dir.sync_all()) {
        warn!(dir = %parent.display(), error = %err, "could not fsync config directory");
    }
}

#[cfg(test)]
#[path = "tests/fs_util.rs"]
mod tests;
