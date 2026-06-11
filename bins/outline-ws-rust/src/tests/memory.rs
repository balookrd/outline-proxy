#[cfg(target_os = "linux")]
#[test]
fn sample_process_thread_count_reports_positive_value() {
    let count = super::sample_process_thread_count();
    assert!(matches!(count, Some(value) if value > 0));
}

#[cfg(target_os = "linux")]
#[test]
fn sample_process_memory_reports_estimated_heap_state() {
    let sample = super::sample_process_memory();
    assert_eq!(sample.heap_mode, "estimated");
    assert!(sample.heap_allocated_bytes.is_some());
    assert!(sample.heap_bytes.is_some());
    assert!(sample.heap_free_bytes.is_none());
}
