/// Linux /proc-based process memory sampling and Prometheus rendering.
///
/// On non-Linux targets the snapshot always returns `None` and rendering is a
/// no-op; the module still compiles everywhere.
use std::fmt::Write;

// ── Public types ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct ProcessMemorySnapshot {
    pub resident_memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub thread_count: Option<u64>,
    pub virtual_stack_bytes: Option<u64>,
    pub virtual_anon_private_bytes: Option<u64>,
    pub virtual_anon_shared_bytes: Option<u64>,
    pub virtual_file_private_bytes: Option<u64>,
    pub virtual_file_shared_bytes: Option<u64>,
    pub virtual_special_bytes: Option<u64>,
    pub top_virtual_mappings: Vec<TopVirtualMapping>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopVirtualMapping {
    pub kind: &'static str,
    pub perms: String,
    pub name: String,
    pub size_bytes: u64,
    pub rss_bytes: u64,
}

// ── Sampling ───────────────────────────────────────────────────────────────────

/// Returns the current process memory snapshot, or `None` on non-Linux targets.
pub fn sample() -> Option<ProcessMemorySnapshot> {
    sample_impl()
}

// ── Prometheus rendering ───────────────────────────────────────────────────────

/// Appends the process-memory metric family to an existing Prometheus text
/// output buffer.  Called from `Metrics::render_prometheus` after the main
/// `handle.render()` output.
pub fn append_to_prometheus_output(out: &mut String, snapshot: &ProcessMemorySnapshot) {
    write_help(
        out,
        "outline_ss_process_resident_memory_bytes",
        "Resident set size of the outline-ss-rust process.",
    );
    write_type(out, "outline_ss_process_resident_memory_bytes", "gauge");
    writeln!(out, "outline_ss_process_resident_memory_bytes {}", snapshot.resident_memory_bytes)
        .ok();

    write_help(
        out,
        "outline_ss_process_virtual_memory_bytes",
        "Virtual memory size of the outline-ss-rust process.",
    );
    write_type(out, "outline_ss_process_virtual_memory_bytes", "gauge");
    writeln!(out, "outline_ss_process_virtual_memory_bytes {}", snapshot.virtual_memory_bytes).ok();

    if let Some(v) = snapshot.thread_count {
        write_help(
            out,
            "outline_ss_process_threads",
            "Thread count of the outline-ss-rust process.",
        );
        write_type(out, "outline_ss_process_threads", "gauge");
        writeln!(out, "outline_ss_process_threads {v}").ok();
    }

    if let Some(v) = snapshot.virtual_stack_bytes {
        write_help(
            out,
            "outline_ss_process_virtual_stack_bytes",
            "Virtual memory bytes currently reserved by process stacks.",
        );
        write_type(out, "outline_ss_process_virtual_stack_bytes", "gauge");
        writeln!(out, "outline_ss_process_virtual_stack_bytes {v}").ok();
    }

    if let Some(v) = snapshot.virtual_anon_private_bytes {
        write_help(
            out,
            "outline_ss_process_virtual_anon_private_bytes",
            "Virtual memory bytes in anonymous private mappings.",
        );
        write_type(out, "outline_ss_process_virtual_anon_private_bytes", "gauge");
        writeln!(out, "outline_ss_process_virtual_anon_private_bytes {v}").ok();
    }

    if let Some(v) = snapshot.virtual_anon_shared_bytes {
        write_help(
            out,
            "outline_ss_process_virtual_anon_shared_bytes",
            "Virtual memory bytes in anonymous shared mappings.",
        );
        write_type(out, "outline_ss_process_virtual_anon_shared_bytes", "gauge");
        writeln!(out, "outline_ss_process_virtual_anon_shared_bytes {v}").ok();
    }

    if let Some(v) = snapshot.virtual_file_private_bytes {
        write_help(
            out,
            "outline_ss_process_virtual_file_private_bytes",
            "Virtual memory bytes in file-backed private mappings.",
        );
        write_type(out, "outline_ss_process_virtual_file_private_bytes", "gauge");
        writeln!(out, "outline_ss_process_virtual_file_private_bytes {v}").ok();
    }

    if let Some(v) = snapshot.virtual_file_shared_bytes {
        write_help(
            out,
            "outline_ss_process_virtual_file_shared_bytes",
            "Virtual memory bytes in file-backed shared mappings.",
        );
        write_type(out, "outline_ss_process_virtual_file_shared_bytes", "gauge");
        writeln!(out, "outline_ss_process_virtual_file_shared_bytes {v}").ok();
    }

    if let Some(v) = snapshot.virtual_special_bytes {
        write_help(
            out,
            "outline_ss_process_virtual_special_bytes",
            "Virtual memory bytes in special kernel/runtime mappings such as [vdso] or [vvar].",
        );
        write_type(out, "outline_ss_process_virtual_special_bytes", "gauge");
        writeln!(out, "outline_ss_process_virtual_special_bytes {v}").ok();
    }

    if !snapshot.top_virtual_mappings.is_empty() {
        write_help(
            out,
            "outline_ss_process_virtual_top_mapping_size_bytes",
            "Top virtual memory mappings by reserved size from /proc/self/smaps.",
        );
        write_type(out, "outline_ss_process_virtual_top_mapping_size_bytes", "gauge");
        write_help(
            out,
            "outline_ss_process_virtual_top_mapping_rss_bytes",
            "RSS contribution of the top virtual memory mappings from /proc/self/smaps.",
        );
        write_type(out, "outline_ss_process_virtual_top_mapping_rss_bytes", "gauge");
        write_help(
            out,
            "outline_ss_process_virtual_top_mapping_gap_bytes",
            "Reserved but currently non-resident bytes of the top virtual memory mappings from /proc/self/smaps.",
        );
        write_type(out, "outline_ss_process_virtual_top_mapping_gap_bytes", "gauge");

        for (index, m) in snapshot.top_virtual_mappings.iter().enumerate() {
            let rank = index + 1;
            let kind = escape(m.kind);
            let perms = escape(&m.perms);
            let name = escape(&m.name);
            writeln!(
                out,
                "outline_ss_process_virtual_top_mapping_size_bytes\
                 {{rank=\"{rank}\",kind=\"{kind}\",perms=\"{perms}\",name=\"{name}\"}} {}",
                m.size_bytes
            )
            .ok();
            writeln!(
                out,
                "outline_ss_process_virtual_top_mapping_rss_bytes\
                 {{rank=\"{rank}\",kind=\"{kind}\",perms=\"{perms}\",name=\"{name}\"}} {}",
                m.rss_bytes
            )
            .ok();
            writeln!(
                out,
                "outline_ss_process_virtual_top_mapping_gap_bytes\
                 {{rank=\"{rank}\",kind=\"{kind}\",perms=\"{perms}\",name=\"{name}\"}} {}",
                m.size_bytes.saturating_sub(m.rss_bytes)
            )
            .ok();
        }
    }
}

// ── Private rendering helpers ──────────────────────────────────────────────────

fn write_help(out: &mut String, name: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").ok();
}

fn write_type(out: &mut String, name: &str, metric_type: &str) {
    writeln!(out, "# TYPE {name} {metric_type}").ok();
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n").replace('"', "\\\"")
}

// ── Linux /proc implementation ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn sample_impl() -> Option<ProcessMemorySnapshot> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let resident_memory_bytes = proc_status_value_bytes(&status, "VmRSS:")?;
    let virtual_memory_bytes = proc_status_value_bytes(&status, "VmSize:")?;
    let thread_count = proc_status_value_u64(&status, "Threads:");
    let diag = procfs_virtual_memory_diagnostics();
    let bd = &diag.breakdown;
    Some(ProcessMemorySnapshot {
        resident_memory_bytes,
        virtual_memory_bytes,
        thread_count,
        virtual_stack_bytes: bd.stack_bytes,
        virtual_anon_private_bytes: bd.anon_private_bytes,
        virtual_anon_shared_bytes: bd.anon_shared_bytes,
        virtual_file_private_bytes: bd.file_private_bytes,
        virtual_file_shared_bytes: bd.file_shared_bytes,
        virtual_special_bytes: bd.special_bytes,
        top_virtual_mappings: diag.top_mappings,
    })
}

#[cfg(not(target_os = "linux"))]
fn sample_impl() -> Option<ProcessMemorySnapshot> {
    None
}

// ── Linux-only types and parsers ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
struct VirtualMemoryBreakdown {
    stack_bytes: Option<u64>,
    anon_private_bytes: Option<u64>,
    anon_shared_bytes: Option<u64>,
    file_private_bytes: Option<u64>,
    file_shared_bytes: Option<u64>,
    special_bytes: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Default)]
struct VirtualMemoryDiagnostics {
    breakdown: VirtualMemoryBreakdown,
    top_mappings: Vec<TopVirtualMapping>,
}

#[cfg(target_os = "linux")]
fn proc_status_value_bytes(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim();
        let kib = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        Some(kib * 1024)
    })
}

#[cfg(target_os = "linux")]
fn proc_status_value_u64(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim();
        rest.split_whitespace().next()?.parse::<u64>().ok()
    })
}

#[cfg(target_os = "linux")]
fn procfs_virtual_memory_diagnostics() -> VirtualMemoryDiagnostics {
    let smaps = match std::fs::read_to_string("/proc/self/smaps") {
        Ok(smaps) => smaps,
        Err(_) => return VirtualMemoryDiagnostics::default(),
    };

    let mut diag = VirtualMemoryDiagnostics::default();
    let mut current_mapping = None;
    let mut current_size_kib = 0_u64;
    let mut current_rss_kib = 0_u64;

    for line in smaps.lines() {
        if is_smaps_mapping_header(line) {
            finalize_mapping(&mut diag, current_mapping.take(), current_size_kib, current_rss_kib);
            current_mapping = parse_smaps_mapping_header(line);
            current_size_kib = 0;
            current_rss_kib = 0;
            continue;
        }
        if smaps_value_kib(line, "Size:").is_some() {
            current_size_kib = smaps_value_kib(line, "Size:").unwrap_or(0);
        } else if smaps_value_kib(line, "Rss:").is_some() {
            current_rss_kib = smaps_value_kib(line, "Rss:").unwrap_or(0);
        }
    }

    finalize_mapping(&mut diag, current_mapping, current_size_kib, current_rss_kib);
    diag.top_mappings
        .sort_by(|l, r| r.size_bytes.cmp(&l.size_bytes).then_with(|| r.rss_bytes.cmp(&l.rss_bytes)));
    diag.top_mappings.truncate(8);
    diag
}

#[cfg(target_os = "linux")]
fn is_smaps_mapping_header(line: &str) -> bool {
    line.split_once('-')
        .and_then(|(start, _)| start.chars().next())
        .is_some_and(|ch| ch.is_ascii_hexdigit())
}

#[cfg(target_os = "linux")]
fn smaps_value_kib(line: &str, key: &str) -> Option<u64> {
    let rest = line.strip_prefix(key)?.trim();
    rest.split_whitespace().next()?.parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn add_optional_u64(slot: &mut Option<u64>, value: u64) {
    *slot = Some(slot.unwrap_or(0).saturating_add(value));
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
enum MappingKind {
    Heap,
    Stack,
    AnonPrivate,
    AnonShared,
    FilePrivate,
    FileShared,
    Special,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct SmapsMappingHeader<'a> {
    kind: MappingKind,
    perms: &'a str,
    pathname: Option<&'a str>,
}

#[cfg(target_os = "linux")]
impl SmapsMappingHeader<'_> {
    fn classify(shared: bool, pathname: Option<&str>) -> MappingKind {
        match pathname {
            Some("[heap]") => MappingKind::Heap,
            Some(p) if p.starts_with("[stack") => MappingKind::Stack,
            Some(p) if p.starts_with("[anon") => {
                if shared { MappingKind::AnonShared } else { MappingKind::AnonPrivate }
            },
            Some(p) if p.starts_with('[') => MappingKind::Special,
            Some(_) => {
                if shared { MappingKind::FileShared } else { MappingKind::FilePrivate }
            },
            None => {
                if shared { MappingKind::AnonShared } else { MappingKind::AnonPrivate }
            },
        }
    }

    fn kind_label(self) -> &'static str {
        match self.kind {
            MappingKind::Heap => "heap",
            MappingKind::Stack => "stack",
            MappingKind::AnonPrivate => "anon_private",
            MappingKind::AnonShared => "anon_shared",
            MappingKind::FilePrivate => "file_private",
            MappingKind::FileShared => "file_shared",
            MappingKind::Special => "special",
        }
    }

    fn display_name(self) -> String {
        match self.pathname {
            Some(path) => truncate_label(path, 96),
            None => "[anonymous]".to_owned(),
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_smaps_mapping_header(line: &str) -> Option<SmapsMappingHeader<'_>> {
    let mut fields = line.split_whitespace();
    fields.next()?;
    let perms = fields.next()?;
    fields.next()?;
    fields.next()?;
    fields.next()?;
    let pathname = fields.next();
    let shared = perms.contains('s');
    Some(SmapsMappingHeader { kind: SmapsMappingHeader::classify(shared, pathname), perms, pathname })
}

#[cfg(target_os = "linux")]
fn finalize_mapping(
    diag: &mut VirtualMemoryDiagnostics,
    mapping: Option<SmapsMappingHeader<'_>>,
    size_kib: u64,
    rss_kib: u64,
) {
    let Some(mapping) = mapping else { return };
    if size_kib == 0 {
        return;
    }
    let size_bytes = size_kib.saturating_mul(1024);
    let rss_bytes = rss_kib.saturating_mul(1024);

    match mapping.kind {
        MappingKind::Heap => {},
        MappingKind::Stack => add_optional_u64(&mut diag.breakdown.stack_bytes, size_bytes),
        MappingKind::AnonPrivate => {
            add_optional_u64(&mut diag.breakdown.anon_private_bytes, size_bytes)
        },
        MappingKind::AnonShared => {
            add_optional_u64(&mut diag.breakdown.anon_shared_bytes, size_bytes)
        },
        MappingKind::FilePrivate => {
            add_optional_u64(&mut diag.breakdown.file_private_bytes, size_bytes)
        },
        MappingKind::FileShared => {
            add_optional_u64(&mut diag.breakdown.file_shared_bytes, size_bytes)
        },
        MappingKind::Special => add_optional_u64(&mut diag.breakdown.special_bytes, size_bytes),
    }

    diag.top_mappings.push(TopVirtualMapping {
        kind: mapping.kind_label(),
        perms: mapping.perms.to_owned(),
        name: mapping.display_name(),
        size_bytes,
        rss_bytes,
    });
}

#[cfg(target_os = "linux")]
fn truncate_label(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }
    let mut s = String::new();
    for ch in value.chars().take(limit.saturating_sub(3)) {
        s.push(ch);
    }
    s.push_str("...");
    s
}
