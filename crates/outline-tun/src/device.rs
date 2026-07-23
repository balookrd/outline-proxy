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

/// Which offload framing the TUN attach negotiated.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TunGso {
    /// `IFF_VNET_HDR` — every read/write carries a `virtio_net_hdr` (write-side
    /// TSO super-segments, read-side GRO framing).
    pub(crate) vnet_hdr: bool,
    /// `TUN_F_TSO4 | TUN_F_TSO6` accepted — the kernel may hand the read loop
    /// coalesced TCP GRO super-packets (RX GRO active on the uplink).
    pub(crate) tcp_gro: bool,
    /// `TUN_F_USO4 | TUN_F_USO6` accepted — the writer may coalesce downlink UDP
    /// into `GSO_UDP_L4` super-segments.
    pub(crate) udp_gso: bool,
}

pub(crate) fn set_nonblocking(file: &std::fs::File) -> Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: `file` borrows the fd for the whole call, so it cannot be closed
    // underneath the syscall; `fcntl` takes the fd by value and dereferences
    // nothing. `F_GETFL` takes no variadic argument (the `0` is ignored) and
    // returns the flag word, so the only failure mode is the checked `< 0`.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL failed");
    }
    // SAFETY: same still-borrowed fd; `F_SETFL` reads its variadic argument as a
    // plain `int` flag word, which is what `flags | O_NONBLOCK` is — `flags`
    // came from the `F_GETFL` above and was checked non-negative, so this only
    // adds a bit to the flags the fd already had. No pointer is involved.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK failed");
    }
    Ok(())
}

/// Opens the TUN device, returning the file plus the active offload framing
/// ([`TunGso`]): `vnet_hdr` when attached with `IFF_VNET_HDR` (write TSO / read
/// GRO framing), and `udp_gso` when the kernel accepted `TUN_F_USO`. All-false
/// on non-Linux.
pub(crate) async fn open_tun_device_with_retry(
    config: &TunConfig,
) -> Result<(std::fs::File, TunGso)> {
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
fn open_tun_device(config: &TunConfig) -> Result<(std::fs::File, TunGso)> {
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
    // *write* (`tun_get_user` → `virtio_net_hdr_to_skb`). RX GRO on the *read*
    // side is opt-in via `TUNSETOFFLOAD` below.
    //
    // `TUNSETIFF` runs on a not-yet-bound fd: on failure the fd stays unbound, so
    // we may retry with a reduced flag set. When `gso` requests `IFF_VNET_HDR`
    // and the attach fails, retry ONCE without it — a kernel lacking vnet_hdr
    // support would otherwise hard-fail here. Degrade to `vnet_hdr = false` only
    // if the plain attach then succeeds; that isolates "kernel lacks
    // IFF_VNET_HDR" from real failures (EBUSY/EPERM), which must propagate
    // unchanged so the busy-retry loop in `open_tun_device_with_retry` still
    // fires on the *original* error.
    let attach = |vnet_hdr: bool| -> std::io::Result<()> {
        let mut flags = IFF_TUN | IFF_NO_PI;
        if vnet_hdr {
            flags |= IFF_VNET_HDR;
        }
        let mut ifreq = IfReq { name: [0; libc::IFNAMSIZ], data: [0; 24] };
        for (index, byte) in name.as_bytes().iter().enumerate() {
            ifreq.name[index] = *byte as libc::c_char;
        }
        // SAFETY: `ifreq.data` is a live, uniquely-owned `[u8; 24]` and the write
        // covers only its first `size_of::<c_short>()` bytes, so it stays in
        // bounds. `write_unaligned` imposes no alignment requirement, which is
        // why it is used here: the array is `u8`-aligned. This reproduces the
        // kernel `ifreq` layout, whose `ifr_ifru` union starts with
        // `ifr_flags: short`; overwriting plain `u8`s drops nothing.
        unsafe {
            std::ptr::write_unaligned(ifreq.data.as_mut_ptr() as *mut libc::c_short, flags);
        }
        // SAFETY: `file` outlives this closure, so the fd is open for the call.
        // `IfReq` is `#[repr(C)]` and mirrors the kernel `struct ifreq`:
        // `IFNAMSIZ` name bytes plus a 24-byte tail covering the `ifr_ifru`
        // union — 40 bytes, exactly `sizeof(struct ifreq)` on LP64 and larger
        // than the 32-byte 32-bit layout, so the kernel's fixed-size copy stays
        // inside the object either way. Every byte is initialised above (zeroed,
        // then name and flags), and `name.len() < IFNAMSIZ` was checked, so the
        // name is NUL-terminated in place. The pointer must be `*mut`: on success
        // `TUNSETIFF` copies the (possibly kernel-assigned) `ifreq` back over the
        // same buffer, and `ifreq` is a fresh local this closure owns uniquely,
        // so that write aliases nothing.
        let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &raw mut ifreq) };
        if result < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    };

    let mut vnet_hdr = config.gso;
    if let Err(primary) = attach(config.gso) {
        if config.gso && attach(false).is_ok() {
            vnet_hdr = false;
            warn!(
                name = %name,
                error = %primary,
                "TUNSETIFF with IFF_VNET_HDR failed; attached without it — TUN GSO/GRO/USO disabled (kernel likely lacks vnet_hdr support)"
            );
        } else {
            return Err(primary).context("TUNSETIFF failed");
        }
    }

    // Offload: set the state EXPLICITLY on every attach — including to 0 — so a
    // persistent TUN device never inherits a stale `TUNSETOFFLOAD` from a
    // previous run (a lingering `tx-udp-segmentation: off [requested on]` after
    // a restart with the flag disabled otherwise keeps breaking UDP).
    //
    // `gro` → `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6`: the kernel may coalesce
    // inbound TCP into >MSS GRO super-packets on read (gso_type TCPV4/6), fed
    // whole into the TCP engine. `uso` → `TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6`:
    // the writer may hand the kernel `GSO_UDP_L4` super-segments (downlink UDP
    // coalescing), and the kernel may hand us UDP GRO on read (the read loop
    // re-segments it). `TUN_F_CSUM` is mandatory for any TSO/USO flag and also
    // enables RX checksum offload, which the read loop recomputes. If the kernel
    // rejects USO (< 6.2) we retry without it so TCP offload survives.
    let mut gso = TunGso { vnet_hdr, tcp_gro: false, udp_gso: false };
    {
        const TUNSETOFFLOAD: libc::c_ulong = 0x400454d0;
        const TUN_F_CSUM: libc::c_uint = 0x01;
        const TUN_F_TSO4: libc::c_uint = 0x02;
        const TUN_F_TSO6: libc::c_uint = 0x04;
        const TUN_F_USO4: libc::c_uint = 0x20;
        const TUN_F_USO6: libc::c_uint = 0x40;
        // Gate on the negotiated `vnet_hdr`, not the requested `config.gso`: if
        // the attach degraded to a plain fd, offload must stay off (and the
        // explicit `set(0)` below still clears any stale TUNSETOFFLOAD from a
        // previous run on a persistent device).
        let want_gro = vnet_hdr && config.gro;
        let want_uso = vnet_hdr && config.uso;
        let mut offload = 0u32;
        if want_gro {
            offload |= TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
        }
        if want_uso {
            offload |= TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6;
        }
        // SAFETY: `file` outlives this closure, so the fd is open for the call.
        // `TUNSETOFFLOAD` is a scalar-argument ioctl: the kernel consumes `arg`
        // as the `TUN_F_*` bitmask itself and never dereferences it, so passing
        // the value (not a pointer) is the correct calling convention here.
        let set = |value: u32| unsafe {
            libc::ioctl(file.as_raw_fd(), TUNSETOFFLOAD as _, value as libc::c_ulong)
        };
        if set(offload) == 0 {
            gso.tcp_gro = want_gro;
            gso.udp_gso = want_uso;
        } else if want_uso {
            // USO likely unsupported on this kernel: drop it, keep GRO/TSO.
            let without_uso = offload & !(TUN_F_USO4 | TUN_F_USO6);
            if set(without_uso) == 0 {
                gso.tcp_gro = want_gro;
                warn!(
                    name = %name,
                    "TUNSETOFFLOAD rejected USO; UDP GSO disabled, TCP offload kept"
                );
            } else {
                warn!(
                    name = %name,
                    error = %std::io::Error::last_os_error(),
                    "TUNSETOFFLOAD failed; TUN offload state may be stale"
                );
            }
        } else {
            warn!(
                name = %name,
                offload,
                error = %std::io::Error::last_os_error(),
                "TUNSETOFFLOAD failed; TUN offload state may be stale"
            );
        }
    }

    // Emit the negotiated offload state unconditionally (info) so the log always
    // answers "is gso/gro/uso really on?" — showing both what the config
    // *requested* and what the kernel actually *accepted* on this attach. A
    // requested flag that reads back `false` here means the kernel (or a degraded
    // plain attach) refused it; the `warn!`s above spell out why. Distinct
    // message + all-flag fields make it greppable (`TUN offload`).
    tracing::info!(
        name = %name,
        req_gso = config.gso,
        req_gro = config.gro,
        req_uso = config.uso,
        vnet_hdr = gso.vnet_hdr,
        rx_gro = gso.tcp_gro,
        udp_gso = gso.udp_gso,
        "TUN offload negotiated"
    );

    Ok((file, gso))
}

#[cfg(not(target_os = "linux"))]
fn open_tun_device(config: &TunConfig) -> Result<(std::fs::File, TunGso)> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&config.path)
        .with_context(|| format!("failed to open {}", config.path.display()))?;
    Ok((file, TunGso::default()))
}
