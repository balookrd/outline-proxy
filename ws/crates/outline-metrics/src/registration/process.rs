use super::macros::{register_labeled, register_scalar};
use prometheus::{Gauge, GaugeVec, IntGaugeVec, Registry};

pub(super) struct ProcessFields {
    pub(super) process_resident_memory_bytes: Gauge,
    pub(super) process_virtual_memory_bytes: Gauge,
    pub(super) process_heap_allocated_bytes: Gauge,
    pub(super) process_heap_mode_info: IntGaugeVec,
    pub(super) process_open_fds: Gauge,
    pub(super) process_threads: Gauge,
    pub(super) process_fd_by_type: GaugeVec,
    pub(super) process_sockets_by_state: IntGaugeVec,
}

pub(super) fn build(registry: &Registry) -> ProcessFields {
    let process_resident_memory_bytes = register_scalar!(
        registry,
        Gauge,
        "outline_ws_rust_process_resident_memory_bytes",
        "Current resident set size of the process in bytes."
    );
    let process_virtual_memory_bytes = register_scalar!(
        registry,
        Gauge,
        "outline_ws_rust_process_virtual_memory_bytes",
        "Current virtual memory size of the process in bytes."
    );
    let process_heap_allocated_bytes = register_scalar!(
        registry,
        Gauge,
        "outline_ws_rust_process_heap_allocated_bytes",
        "Current allocated heap bytes when available; may be estimated from process memory maps."
    );
    let process_heap_mode_info = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_process_heap_mode_info",
        "Allocator heap sampling mode for the current process.",
        ["mode"]
    );
    let process_open_fds = register_scalar!(
        registry,
        Gauge,
        "outline_ws_rust_process_open_fds",
        "Current number of open file descriptors used by the process."
    );
    let process_threads = register_scalar!(
        registry,
        Gauge,
        "outline_ws_rust_process_threads",
        "Current number of threads used by the process."
    );
    let process_fd_by_type = register_labeled!(
        registry,
        GaugeVec,
        "outline_ws_rust_process_fd_by_type",
        "Current number of open file descriptors by descriptor type.",
        ["kind"]
    );
    let process_sockets_by_state = register_labeled!(
        registry,
        IntGaugeVec,
        "outline_ws_rust_process_sockets_by_state",
        "Current count of TCP/UDP sockets owned by the process, broken down by protocol, address family and kernel state.",
        ["protocol", "family", "state"]
    );

    ProcessFields {
        process_resident_memory_bytes,
        process_virtual_memory_bytes,
        process_heap_allocated_bytes,
        process_heap_mode_info,
        process_open_fds,
        process_threads,
        process_fd_by_type,
        process_sockets_by_state,
    }
}
