#[cfg(target_os = "linux")]
#[test]
fn sample_process_thread_count_reports_positive_value() {
    let count = super::sample_process_thread_count();
    assert!(matches!(count, Some(value) if value > 0));
}

/// With jemalloc the figures come from the allocator, so all three are present
/// and `free` is the memory it holds without handing out — the fragmentation
/// number the estimating path cannot produce.
#[cfg(all(target_os = "linux", feature = "jemalloc"))]
#[test]
fn sample_process_memory_reports_exact_heap_state() {
    let sample = super::sample_process_memory();
    assert_eq!(sample.heap_mode, "exact");
    assert!(sample.heap_allocated_bytes.is_some());
    assert!(sample.heap_bytes.is_some());
    assert!(
        sample.heap_free_bytes.is_some(),
        "jemalloc reports resident, so free is derivable"
    );
    // resident >= allocated, so the derived free figure can never wrap.
    assert!(sample.heap_bytes >= sample.heap_allocated_bytes);
}

/// Without jemalloc the sampler reads `VmData` — every anonymous mapping the
/// process owns, not the heap. It must keep saying so through `heap_mode`, and
/// must not invent a free figure it has no way to know.
#[cfg(all(target_os = "linux", not(feature = "jemalloc")))]
#[test]
fn sample_process_memory_reports_estimated_heap_state() {
    let sample = super::sample_process_memory();
    assert_eq!(sample.heap_mode, "estimated");
    assert!(sample.heap_allocated_bytes.is_some());
    assert!(sample.heap_bytes.is_some());
    assert!(sample.heap_free_bytes.is_none());
}

/// jemalloc's page has to equal the kernel's. The build pins it for aarch64
/// Linux in `.cargo/config.toml` (jemalloc 5.3.1 would otherwise pick 64 KiB
/// there); this fails if that pin stops reaching the build.
#[cfg(all(unix, feature = "jemalloc"))]
#[test]
fn jemalloc_page_matches_the_kernel_page() {
    let (jemalloc, kernel) = super::allocator_page_sizes().expect("both page sizes are readable");
    assert_eq!(jemalloc, kernel, "jemalloc page {jemalloc} vs kernel page {kernel}");
}
