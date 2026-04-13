//! Socket mark (`SO_MARK`) helpers, Linux-only.
//!
//! Extracted into a separate module so both `server` and `nat` can use them
//! without creating a circular dependency.

#[cfg(unix)]
pub(crate) fn apply_fwmark_if_needed<T>(socket: &T, fwmark: Option<u32>) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    if let Some(fwmark) = fwmark { apply_fwmark(socket, fwmark) } else { Ok(()) }
}

#[cfg(not(unix))]
pub(crate) fn apply_fwmark_if_needed<T>(_socket: &T, fwmark: Option<u32>) -> std::io::Result<()> {
    if fwmark.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fwmark is only supported on Unix/Linux",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_fwmark<T>(socket: &T, fwmark: u32) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    let value: libc::c_uint = fwmark;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn apply_fwmark<T>(_socket: &T, _fwmark: u32) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "fwmark is only supported on Linux"))
}
