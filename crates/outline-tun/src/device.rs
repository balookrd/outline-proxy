//! TUN device open / lifecycle helpers.
//!
//! Handles OS-specific attach (TUNSETIFF on Linux, plain open elsewhere),
//! EBUSY retry when another process is mid-detach, and `O_NONBLOCK` setup
//! so the fd can be registered with the tokio reactor.

use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::time::Duration;

#[cfg(target_os = "linux")]
use anyhow::anyhow;
use anyhow::{Context, Result, bail};
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

/// Opens the TUN device, returning the file plus whether it was attached with
/// `IFF_VNET_HDR` (so reads/writes carry a `virtio_net_hdr` prefix and the
/// writer may emit TSO super-segments). Only `true` on Linux with `config.gso`.
pub(crate) async fn open_tun_device_with_retry(
    config: &TunConfig,
) -> Result<(std::fs::File, bool)> {
    for attempt in 0..=TUN_OPEN_BUSY_RETRIES {
        match open_tun_device(config) {
            Ok(result) => return Ok(result),
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
fn open_tun_device(config: &TunConfig) -> Result<(std::fs::File, bool)> {
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const IFF_VNET_HDR: libc::c_short = 0x4000;
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

    // TUN GSO: `IFF_VNET_HDR` makes every read/write carry a `virtio_net_hdr`
    // prefix, which is all the kernel needs to accept a TSO super-segment on
    // *write* (`tun_get_user` → `virtio_net_hdr_to_skb`). We deliberately do NOT
    // request `TUNSETOFFLOAD`: that only affects the *read* side (it would let
    // the kernel hand us GRO super-packets to resegment); without it the kernel
    // segments to <=MSS before we read, so the read path never sees GSO.
    let mut flags = IFF_TUN | IFF_NO_PI;
    if config.gso {
        flags |= IFF_VNET_HDR;
    }

    let mut ifreq = IfReq { name: [0; libc::IFNAMSIZ], data: [0; 24] };
    for (index, byte) in name.as_bytes().iter().enumerate() {
        ifreq.name[index] = *byte as libc::c_char;
    }
    unsafe {
        std::ptr::write_unaligned(ifreq.data.as_mut_ptr() as *mut libc::c_short, flags);
    }

    let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &ifreq) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("TUNSETIFF failed");
    }
    Ok((file, config.gso))
}

#[cfg(not(target_os = "linux"))]
fn open_tun_device(config: &TunConfig) -> Result<(std::fs::File, bool)> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))?;
    Ok((file, false))
}
