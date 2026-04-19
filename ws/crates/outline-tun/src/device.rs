//! TUN device open / lifecycle helpers.
//!
//! Handles OS-specific attach (TUNSETIFF on Linux, plain open elsewhere),
//! EBUSY retry when another process is mid-detach, and `O_NONBLOCK` setup
//! so the fd can be registered with the tokio reactor.

use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::time::Duration;

use anyhow::{Context, Result, bail};
#[cfg(target_os = "linux")]
use anyhow::anyhow;
use tracing::warn;

use crate::config::TunConfig;

pub(crate) const EBUSY_OS_ERROR: i32 = 16;
const TUN_OPEN_BUSY_RETRIES: usize = 20;
const TUN_OPEN_BUSY_RETRY_DELAY: Duration = Duration::from_millis(250);

pub(crate) fn set_nonblocking(file: &std::fs::File) -> Result<()> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL failed");
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK failed");
    }
    Ok(())
}

pub(crate) async fn open_tun_device_with_retry(config: &TunConfig) -> Result<std::fs::File> {
    for attempt in 0..=TUN_OPEN_BUSY_RETRIES {
        match open_tun_device(config) {
            Ok(file) => return Ok(file),
            Err(error) if is_tun_device_busy_error(&error) && attempt < TUN_OPEN_BUSY_RETRIES => {
                warn!(
                    name = config.name.as_deref().unwrap_or("n/a"),
                    path = %config.path.display(),
                    attempt = attempt + 1,
                    retry_in_ms = TUN_OPEN_BUSY_RETRY_DELAY.as_millis(),
                    "TUN interface is busy, retrying attach"
                );
                tokio::time::sleep(TUN_OPEN_BUSY_RETRY_DELAY).await;
            },
            Err(error) if is_tun_device_busy_error(&error) => {
                bail!(
                    "TUN interface {} remained busy after {} retries; another process may still own it: {error:#}",
                    config.name.as_deref().unwrap_or("n/a"),
                    TUN_OPEN_BUSY_RETRIES
                );
            },
            Err(error) => return Err(error),
        }
    }
    unreachable!("retry loop always returns");
}

pub(crate) fn is_tun_device_busy_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|source| source.downcast_ref::<std::io::Error>())
        .any(|io_error| io_error.raw_os_error() == Some(EBUSY_OS_ERROR))
}

#[cfg(target_os = "linux")]
fn open_tun_device(config: &TunConfig) -> Result<std::fs::File> {
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x400454ca;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        data: [u8; 24],
    }

    let name = config
        .name
        .as_ref()
        .ok_or_else(|| anyhow!("missing tun.name for Linux TUN attach"))?;
    if name.len() >= libc::IFNAMSIZ {
        bail!("tun.name is too long for Linux ifreq: {}", name);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))?;

    let mut ifreq = IfReq { name: [0; libc::IFNAMSIZ], data: [0; 24] };
    for (index, byte) in name.as_bytes().iter().enumerate() {
        ifreq.name[index] = *byte as libc::c_char;
    }
    unsafe {
        std::ptr::write_unaligned(
            ifreq.data.as_mut_ptr() as *mut libc::c_short,
            IFF_TUN | IFF_NO_PI,
        );
    }

    let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &ifreq) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF failed");
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn open_tun_device(config: &TunConfig) -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))
}
