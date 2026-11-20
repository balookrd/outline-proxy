use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Monitors live transmitted and received network bytes using Win32 IP Helper API.
pub struct TrafficMonitor {
    is_tracking: AtomicBool,
    is_tun: AtomicBool,
    base_tx: AtomicU64,
    base_rx: AtomicU64,
}

impl Default for TrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMonitor {
    pub fn new() -> Self {
        Self {
            is_tracking: AtomicBool::new(false),
            is_tun: AtomicBool::new(false),
            base_tx: AtomicU64::new(0),
            base_rx: AtomicU64::new(0),
        }
    }

    /// Starts tracking from the current network interface baseline.
    pub fn start(&self, is_tun: bool) {
        self.is_tun.store(is_tun, Ordering::Relaxed);
        let (tx, rx) = read_system_traffic_bytes(is_tun);
        self.base_tx.store(tx, Ordering::Relaxed);
        self.base_rx.store(rx, Ordering::Relaxed);
        self.is_tracking.store(true, Ordering::Relaxed);
    }

    /// Stops tracking and clears baselines.
    pub fn stop(&self) {
        self.is_tracking.store(false, Ordering::Relaxed);
        self.base_tx.store(0, Ordering::Relaxed);
        self.base_rx.store(0, Ordering::Relaxed);
    }

    /// Returns (tx_bytes, rx_bytes) transmitted/received since tracking started.
    pub fn current_bytes(&self) -> (u64, u64) {
        if !self.is_tracking.load(Ordering::Relaxed) {
            return (0, 0);
        }
        let is_tun = self.is_tun.load(Ordering::Relaxed);
        let (now_tx, now_rx) = read_system_traffic_bytes(is_tun);
        let base_tx = self.base_tx.load(Ordering::Relaxed);
        let base_rx = self.base_rx.load(Ordering::Relaxed);
        let tx = now_tx.saturating_sub(base_tx);
        let rx = now_rx.saturating_sub(base_rx);
        (tx, rx)
    }
}

/// Reads total interface bytes via GetIfTable2 on Windows.
pub fn read_system_traffic_bytes(target_is_tun: bool) -> (u64, u64) {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::*;
        let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        if GetIfTable2(&mut table_ptr) != 0 || table_ptr.is_null() {
            return (0, 0);
        }

        let num_entries = (*table_ptr).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), num_entries);

        let mut total_tx: u64 = 0;
        let mut total_rx: u64 = 0;
        let mut found_tun = false;

        if target_is_tun {
            // First attempt: try to find dedicated Wintun / Outline virtual adapter
            for row in rows {
                let alias = String::from_utf16_lossy(&row.Alias);
                let desc = String::from_utf16_lossy(&row.Description);
                let is_tun = alias.contains("Outline")
                    || alias.contains("Wintun")
                    || desc.contains("Outline")
                    || desc.contains("Wintun");
                if is_tun {
                    total_tx += row.OutOctets;
                    total_rx += row.InOctets;
                    found_tun = true;
                }
            }
        }

        if !found_tun {
            // SOCKS5 mode or fallback: sum active non-loopback network interfaces (OperStatus Up == 1, Loopback == 24)
            for row in rows {
                if row.OperStatus == 1 && row.Type != 24 {
                    total_tx += row.OutOctets;
                    total_rx += row.InOctets;
                }
            }
        }

        FreeMibTable(table_ptr as *const std::ffi::c_void);
        (total_tx, total_rx)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = target_is_tun;
        (0, 0)
    }
}
