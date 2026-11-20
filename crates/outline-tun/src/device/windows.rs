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
    let guid = 0xdeadbeef_u128; // Deterministic GUID for stable interface

    let adapter = match wintun::Adapter::open(&wintun, adapter_name) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, adapter_name, pool_name, Some(guid))
            .context("failed to create Wintun adapter")?,
    };

    // 4 MiB ring buffer session
    let session = Arc::new(
        adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .context("failed to start Wintun session")?,
    );

    let read_event = session
        .get_read_wait_event()
        .context("failed to get Wintun read wait event")?;

    info!(adapter = %adapter_name, mtu = config.mtu, "Wintun interface initialized");

    Ok((
        WintunDevice { session, read_event },
        TunGso {
            vnet_hdr: false,
            tcp_gro: false,
            udp_gso: false,
            af_hdr: false,
        },
    ))
}

/// Alias for `open_wintun_device` conforming to the generic interface.
pub fn open_tun_device(config: &TunConfig) -> Result<(TunDevice, TunGso)> {
    open_wintun_device(config)
}
