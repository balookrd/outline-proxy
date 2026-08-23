use super::{HeapSnapshot, ProcessMemorySnapshot, append_to_prometheus_output};

fn render(snapshot: &ProcessMemorySnapshot) -> String {
    let mut out = String::new();
    append_to_prometheus_output(&mut out, snapshot);
    out
}

/// The fragmentation figure is what this family exists for: `resident` is what
/// the allocator holds from the OS, `allocated` what it handed out, and the
/// difference is memory nobody is using. On mimalloc that difference was 87-90%
/// of the process, invisible from `/proc`.
#[test]
fn heap_free_is_the_gap_between_resident_and_allocated() {
    let rendered = render(&ProcessMemorySnapshot {
        heap: Some(HeapSnapshot {
            allocated_bytes: 30 * 1024 * 1024,
            resident_bytes: 46 * 1024 * 1024,
        }),
        ..Default::default()
    });

    assert!(rendered.contains("outline_ss_process_heap_allocated_bytes 31457280"));
    assert!(rendered.contains("outline_ss_process_heap_resident_bytes 48234496"));
    assert!(rendered.contains("outline_ss_process_heap_free_bytes 16777216"));
}

/// `resident < allocated` should not happen, but the subtraction must not wrap
/// into a nonsense gauge if a future allocator ever reports it that way.
#[test]
fn heap_free_saturates_instead_of_wrapping() {
    let rendered = render(&ProcessMemorySnapshot {
        heap: Some(HeapSnapshot { allocated_bytes: 100, resident_bytes: 40 }),
        ..Default::default()
    });

    assert!(rendered.contains("outline_ss_process_heap_free_bytes 0"));
}

/// Builds without jemalloc have no way to know any of this. They must emit
/// nothing rather than zeros — a zero here would read as "the allocator holds
/// nothing spare", which is exactly the wrong conclusion.
#[test]
fn a_build_without_allocator_stats_emits_no_heap_series() {
    let rendered = render(&ProcessMemorySnapshot::default());

    assert!(!rendered.contains("outline_ss_process_heap_"));
    // The rest of the family still renders, so the absence is specific.
    assert!(rendered.contains("outline_ss_process_resident_memory_bytes"));
}
