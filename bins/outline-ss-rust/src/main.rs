use anyhow::Result;

// The binary owns the global allocator; keep dependency-level allocator
// features such as sockudo-ws/mimalloc disabled to avoid duplicate definitions.
#[cfg(all(feature = "mimalloc", feature = "jemalloc"))]
compile_error!("features `mimalloc` and `jemalloc` are mutually exclusive: pick one allocator");

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read once at startup; mirrors `outline-ws-rust`.
///
/// `background_thread` is the load-bearing part: without it decay only
/// advances when the allocator is called, so a relay that goes quiet right
/// after a burst keeps its high-water mark — the very trap the mimalloc purge
/// thread below was written to work around. `MALLOC_CONF` from the environment
/// still overrides this, so a node can be retuned without a rebuild.
#[cfg(feature = "jemalloc")]
#[unsafe(export_name = "malloc_conf")]
pub static MALLOC_CONF: &[u8] = b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:0\0";

/// Period between forced mimalloc reclamation passes. 10 s keeps the window
/// where post-burst RSS lingers above a cgroup MemoryHigh short; the heap walk
/// itself is milliseconds, negligible at this cadence.
#[cfg(feature = "mimalloc")]
const MIMALLOC_PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawn a low-frequency background thread that forces mimalloc to return
/// decommittable memory to the OS.
///
/// Only for the mimalloc build: jemalloc's own background thread does this,
/// and does it per extent rather than per arena, which is why it can return
/// memory this loop could not.
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
#[cfg(feature = "mimalloc")]
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
    #[cfg(feature = "mimalloc")]
    spawn_mimalloc_maintenance();
    outline_ss_rust::run()
}
