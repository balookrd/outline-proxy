use prometheus::{Gauge, GaugeVec, IntGaugeVec, Opts, Registry};

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
    let process_resident_memory_bytes = Gauge::with_opts(Opts::new(
        "outline_ws_rust_process_resident_memory_bytes",
        "Current resident set size of the process in bytes.",
    ))
    .expect("process_resident_memory_bytes metric");

    let process_virtual_memory_bytes = Gauge::with_opts(Opts::new(
        "outline_ws_rust_process_virtual_memory_bytes",
        "Current virtual memory size of the process in bytes.",
    ))
    .expect("process_virtual_memory_bytes metric");

    let process_heap_allocated_bytes = Gauge::with_opts(Opts::new(
        "outline_ws_rust_process_heap_allocated_bytes",
        "Current allocated heap bytes when available; may be estimated from process memory maps.",
    ))
    .expect("process_heap_allocated_bytes metric");

    let process_heap_mode_info = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_process_heap_mode_info",
            "Allocator heap sampling mode for the current process.",
        ),
        &["mode"],
    )
    .expect("process_heap_mode_info metric");

    let process_open_fds = Gauge::with_opts(Opts::new(
        "outline_ws_rust_process_open_fds",
        "Current number of open file descriptors used by the process.",
    ))
    .expect("process_open_fds metric");

    let process_threads = Gauge::with_opts(Opts::new(
        "outline_ws_rust_process_threads",
        "Current number of threads used by the process.",
    ))
    .expect("process_threads metric");

    let process_fd_by_type = GaugeVec::new(
        Opts::new(
            "outline_ws_rust_process_fd_by_type",
            "Current number of open file descriptors by descriptor type.",
        ),
        &["kind"],
    )
    .expect("process_fd_by_type metric");

    let process_sockets_by_state = IntGaugeVec::new(
        Opts::new(
            "outline_ws_rust_process_sockets_by_state",
            "Current count of TCP/UDP sockets owned by the process, broken down by protocol, address family and kernel state.",
        ),
        &["protocol", "family", "state"],
    )
    .expect("process_sockets_by_state metric");

    registry
        .register(Box::new(process_resident_memory_bytes.clone()))
        .expect("register process_resident_memory_bytes");
    registry
        .register(Box::new(process_virtual_memory_bytes.clone()))
        .expect("register process_virtual_memory_bytes");
    registry
        .register(Box::new(process_heap_allocated_bytes.clone()))
        .expect("register process_heap_allocated_bytes");
    registry
        .register(Box::new(process_heap_mode_info.clone()))
        .expect("register process_heap_mode_info");
    registry
        .register(Box::new(process_open_fds.clone()))
        .expect("register process_open_fds");
    registry
        .register(Box::new(process_threads.clone()))
        .expect("register process_threads");
    registry
        .register(Box::new(process_fd_by_type.clone()))
        .expect("register process_fd_by_type");
    registry
        .register(Box::new(process_sockets_by_state.clone()))
        .expect("register process_sockets_by_state");

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
