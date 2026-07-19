use anyhow::Result;

// The binary owns the global allocator; keep dependency-level allocator
// features such as sockudo-ws/mimalloc disabled to avoid duplicate definitions.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Period between forced mimalloc reclamation passes. 10 s keeps the window
/// where post-burst RSS lingers above a cgroup MemoryHigh short; the heap walk
/// itself is milliseconds, negligible at this cadence.
const MIMALLOC_PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawn a low-frequency background thread that forces mimalloc to return
/// decommittable memory to the OS.
///
/// mimalloc purges freed pages lazily, driven by allocator activity
/// (alloc/free traffic). A relay that goes quiet right after a large
/// transient burst — e.g. thousands of NAT sessions or relay buffers created
/// and then drained together — can otherwise sit on its high-water-mark RSS
/// indefinitely, because nothing triggers the delayed purge. A periodic
/// `mi_collect(true)` forces that reclamation; mimalloc already decommits on
/// purge by default (`mi_option_purge_decommits = 1`), so reclaimed pages are
/// handed back to the kernel rather than merely reset. Mirrors the same loop
/// in `outline-ws-rust`.
fn spawn_mimalloc_maintenance() {
    let spawned = std::thread::Builder::new()
        .name("mimalloc-purge".to_owned())
        .spawn(|| {
            loop {
                std::thread::sleep(MIMALLOC_PURGE_INTERVAL);
                // SAFETY: `mi_collect` is a thread-safe mimalloc entry point
                // with no preconditions. `force = true` reclaims empty
                // segments and returns decommitted memory to the OS.
                unsafe { libmimalloc_sys::mi_collect(true) };
            }
        });
    if let Err(error) = spawned {
        // Runs before `run()` installs the tracing subscriber, so plain
        // stderr is the only sink that cannot lose this.
        eprintln!("warning: failed to spawn mimalloc maintenance thread: {error}");
    }
}

fn main() -> Result<()> {
    spawn_mimalloc_maintenance();
    outline_ss_rust::run()
}
