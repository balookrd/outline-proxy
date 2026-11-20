//! Wintun device adapter for Windows.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tracing::info;

use crate::config::TunConfig;
use crate::device::TunGso;

/// Wintun virtual network adapter and active session handle.
pub struct WintunDevice {
    pub session: Arc<wintun::Session>,
    pub read_event: windows_sys::Win32::Foundation::HANDLE,
    pub if_index: u32,
}

// SAFETY: HANDLE is a Win32 kernel object handle which is thread-safe,
// and wintun::Session is thread-safe.
unsafe impl Send for WintunDevice {}
unsafe impl Sync for WintunDevice {}

pub type TunDevice = WintunDevice;

impl WintunDevice {
    pub fn session(&self) -> &Arc<wintun::Session> {
        &self.session
    }

    pub fn read_event(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.read_event
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    /// Read a packet from the Wintun ring buffer into `buf`.
    ///
    /// If no packet is ready, awaits notification on the read event.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            if let Some(packet) = self
                .session
                .try_receive()
                .context("failed to receive packet from Wintun")?
            {
                let bytes = packet.bytes();
                if buf.len() < bytes.len() {
                    bail!("destination buffer too small: {} < {}", buf.len(), bytes.len());
                }
                let len = bytes.len();
                buf[..len].copy_from_slice(bytes);
                return Ok(len);
            }
            let read_event = self.read_event as usize;
            tokio::task::spawn_blocking(move || unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(
                    read_event as windows_sys::Win32::Foundation::HANDLE,
                    windows_sys::Win32::System::Threading::INFINITE,
                );
            })
            .await
            .context("spawn_blocking failed for Wintun read event")?;
        }
    }

    /// Write an IP packet into the Wintun session.
    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let size = u16::try_from(packet.len()).context("packet too large for Wintun")?;
        let mut pkt = self
            .session
            .allocate_send_packet(size)
            .context("failed to allocate Wintun send packet")?;
        pkt.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(pkt);
        Ok(())
    }

    /// Async write helper matching the TunDevice interface.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.write_packet(buf)?;
        Ok(buf.len())
    }
}

/// Opens or creates a Wintun adapter and starts a session.
pub fn open_wintun_device(config: &TunConfig) -> Result<(WintunDevice, TunGso)> {
    let wintun = unsafe { wintun::load() }.context(
        "failed to load wintun.dll. Ensure wintun.dll is present in the working directory or System32",
    )?;

    let adapter_name = config.name.as_deref().unwrap_or("OutlineProxy");
    let pool_name = "OutlineProxyPool";

    let adapter = match wintun::Adapter::open(&wintun, adapter_name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, adapter_name, pool_name, None)
            .context("failed to create Wintun adapter")?,
    };

    let if_index = adapter
        .get_adapter_index()
        .context("failed to get Wintun adapter index")?;

    // 4 MiB ring buffer session
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .context("failed to start Wintun session")?,
    );

    let raw_event = session
        .get_read_wait_event()
        .context("failed to get Wintun read wait event")?;
    let read_event = raw_event as windows_sys::Win32::Foundation::HANDLE;

    // Assign static IPv4 to the Wintun adapter so Windows networking subsystem can bind routes to it
    if let Err(err) = configure_wintun_ip(
        if_index,
        std::net::Ipv4Addr::new(10, 0, 85, 2),
        std::net::Ipv4Addr::new(255, 255, 255, 0),
    ) {
        tracing::warn!(if_index, error = %err, "Failed to configure Wintun IP via netsh");
    }

    info!(adapter = %adapter_name, if_index, mtu = config.mtu, "Wintun interface initialized");

    Ok((
        WintunDevice { session, read_event, if_index },
        TunGso {
            vnet_hdr: false,
            tcp_gro: false,
            udp_gso: false,
            af_hdr: false,
        },
    ))
}

/// Configures static IPv4 address on the specified Wintun interface via netsh.
pub fn configure_wintun_ip(
    if_index: u32,
    ip: std::net::Ipv4Addr,
    mask: std::net::Ipv4Addr,
) -> Result<()> {
    let if_arg = format!("name={if_index}");
    let addr_arg = format!("address={ip}");
    let mask_arg = format!("mask={mask}");

    let mut status = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "address",
            &if_arg,
            "source=static",
            &addr_arg,
            &mask_arg,
            "gateway=none",
        ])
        .status()
        .with_context(|| {
            format!("failed to execute netsh to assign IP to Wintun interface {if_index}")
        })?;

    if !status.success() {
        tracing::warn!(if_index, %ip, %status, "netsh set address with ifIndex returned non-zero, trying adapter name");
        status = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "address",
                "name=\"OutlineProxy\"",
                "source=static",
                &addr_arg,
                &mask_arg,
                "gateway=none",
            ])
            .status()
            .with_context(|| "failed to execute netsh fallback by adapter name")?;
    }

    if !status.success() {
        tracing::warn!(if_index, %ip, %status, "netsh set address returned non-zero");
    } else {
        tracing::info!(if_index, %ip, "Assigned static IP to Wintun adapter");
        // Give Windows network stack a brief moment to finish Duplicate Address Detection (DAD)
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    Ok(())
}

/// Alias for `open_wintun_device` conforming to the generic interface.
pub fn open_tun_device(config: &TunConfig) -> Result<(TunDevice, TunGso)> {
    open_wintun_device(config)
}
