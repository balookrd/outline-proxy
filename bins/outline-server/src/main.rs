use anyhow::Result;

// The binary owns the global allocator; keep dependency-level allocator
// features such as sockudo-ws/mimalloc disabled to avoid duplicate definitions.
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc tuning, read once at startup; mirrors `outline-client`.
///
/// `background_thread` is the load-bearing part: without it decay only
/// advances when the allocator is called, so a relay that goes quiet right
/// after a burst keeps its high-water mark. `MALLOC_CONF` from the environment
/// still overrides this, so a node can be retuned without a rebuild.
///
/// `calloc_madvise_threshold:0` keeps jemalloc 5.3.0's zeroed-allocation
/// behaviour: since 5.3.1 a reused dirty extent under the threshold is zeroed
/// with `memset`, faulting in every page of a mostly idle `vec![0; N]` buffer
/// (see `outline-client`'s `MALLOC_CONF` for the fleet numbers).
#[cfg(feature = "jemalloc")]
#[unsafe(export_name = "malloc_conf")]
pub static MALLOC_CONF: &[u8] =
    b"background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:0,calloc_madvise_threshold:0\0";

fn main() -> Result<()> {
    outline_server::run()
}

#[cfg(test)]
#[path = "tests/main.rs"]
mod tests;
