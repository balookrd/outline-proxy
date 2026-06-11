use anyhow::Result;

// The binary owns the global allocator; keep dependency-level allocator
// features such as sockudo-ws/mimalloc disabled to avoid duplicate definitions.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    outline_ss_rust::run()
}
