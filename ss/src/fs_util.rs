//! Small filesystem helpers shared across modules.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

/// Write `bytes` to `path` atomically: first to a sibling `.{name}.tmp`, then
/// rename over `path`. Prevents leaving a half-written file behind if the
/// process is killed mid-write.
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
    fs::write(&tmp, bytes)
        .with_context(|| format!("failed to write temp file {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| {
        format!("failed to rename {} -> {}", tmp.display(), path.display())
    })?;
    Ok(())
}
