use std::path::PathBuf;
use std::sync::Arc;

use tracing::warn;

use outline_uplink::StateStore;

pub(super) async fn init(path: Option<PathBuf>) -> Option<Arc<StateStore>> {
    let path = path?;

    // Probe write access before committing to the path.  On many
    // deployments the config lives in /etc/ (owned by root) while the
    // proxy runs as an unprivileged user — fail clearly instead of
    // silently dropping every write later.
    let probe = {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        // Restrict newly created state files to the process owner.
        // The file contains uplink names; readable-by-all is harmless
        // but there's no reason to be permissive.
        // tokio::fs::OpenOptions exposes mode() as an inherent method on Unix.
        #[cfg(unix)]
        opts.mode(0o600);
        opts.open(&path).await
    };

    match probe {
        Ok(_) => {
            let store: Arc<StateStore> = StateStore::load_or_default(path).await;
            store.clone().spawn_writer();
            Some(store)
        },
        Err(e) => {
            warn!(
                path = ?path,
                error = %e,
                "cannot write uplink state file — active-uplink selection \
                 will not persist across restarts. \
                 Fix permissions or point state_path to a writable location."
            );
            None
        },
    }
}
