/// `calloc_madvise_threshold` defaults to 8 MiB in jemalloc 5.3.1, and that
/// default keeps idle zeroed buffers fully resident (see `MALLOC_CONF`).
/// jemalloc exposes no mallctl for it, so the setting is checked in the string
/// itself.
#[cfg(feature = "jemalloc")]
#[test]
fn malloc_conf_disables_the_calloc_memset_threshold() {
    let conf = std::str::from_utf8(super::MALLOC_CONF).expect("MALLOC_CONF is ASCII");
    let conf = conf.strip_suffix('\0').expect("MALLOC_CONF is NUL-terminated");
    assert!(conf.split(',').any(|pair| pair == "calloc_madvise_threshold:0"), "{conf}");
}

/// The built-in `malloc_conf` symbol has to reach jemalloc, or none of its
/// settings apply; `background_thread` stands in for the whole string. Linux
/// only: elsewhere tikv-jemalloc-sys prefixes its symbols and the unprefixed
/// `malloc_conf` is not read.
#[cfg(all(target_os = "linux", feature = "jemalloc"))]
#[test]
fn malloc_conf_reaches_jemalloc() {
    // SAFETY: `opt.background_thread` is a read-only `bool` mallctl.
    let background = unsafe { tikv_jemalloc_ctl::raw::read::<bool>(b"opt.background_thread\0") }
        .expect("opt.background_thread is readable");
    assert!(background, "built-in malloc_conf was not applied");
}
