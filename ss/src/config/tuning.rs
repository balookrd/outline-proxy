use anyhow::{Result, bail};
use serde::Deserialize;

/// Named bundle of HTTP/2 and HTTP/3 resource limits. Pick the smallest
/// profile that still saturates your expected bandwidth×RTT — larger
/// profiles scale memory per connection linearly.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, clap::ValueEnum, Deserialize)]
pub enum TuningPreset {
    #[value(name = "small")]
    #[serde(rename = "small")]
    Small,
    #[value(name = "medium")]
    #[serde(rename = "medium")]
    Medium,
    #[value(name = "large")]
    #[serde(rename = "large")]
    #[default]
    Large,
}

impl TuningPreset {
    pub fn preset(self) -> TuningProfile {
        match self {
            Self::Small => TuningProfile::SMALL,
            Self::Medium => TuningProfile::MEDIUM,
            Self::Large => TuningProfile::LARGE,
        }
    }
}

/// Resolved HTTP/2 and HTTP/3 resource limits used by the server transports.
///
/// Upper-bound memory per connection is roughly `h3_connection_window_bytes`
/// (flow-control) + `h3_max_backpressure_bytes` (write-side) + datagram
/// buffers, so `profile × max_expected_connections` should fit in the host's
/// available RAM with headroom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TuningProfile {
    pub h2_stream_window_bytes: u32,
    pub h2_connection_window_bytes: u32,
    pub h2_max_send_buf_size: usize,

    pub h3_stream_window_bytes: u64,
    pub h3_connection_window_bytes: u64,
    pub h3_max_concurrent_bidi_streams: u32,
    pub h3_max_concurrent_uni_streams: u32,
    pub h3_write_buffer_bytes: usize,
    pub h3_max_backpressure_bytes: usize,
    pub h3_udp_socket_buffer_bytes: usize,

    /// TTL in seconds used to compute `client_active` / `client_up` metrics.
    pub client_active_ttl_secs: u64,
    /// How long a UDP NAT entry is kept alive after the last outbound datagram.
    pub udp_nat_idle_timeout_secs: u64,
    /// Process-wide ceiling on in-flight UDP relay tasks across all WebSocket
    /// sessions. `0` disables the global cap.
    pub udp_max_concurrent_relay_tasks: usize,
}

impl TuningProfile {
    /// Conservative profile for shared / low-memory hosts.
    pub const SMALL: Self = Self {
        h2_stream_window_bytes: 1024 * 1024,
        h2_connection_window_bytes: 4 * 1024 * 1024,
        h2_max_send_buf_size: 1024 * 1024,
        h3_stream_window_bytes: 1024 * 1024,
        h3_connection_window_bytes: 4 * 1024 * 1024,
        h3_max_concurrent_bidi_streams: 256,
        h3_max_concurrent_uni_streams: 128,
        h3_write_buffer_bytes: 128 * 1024,
        h3_max_backpressure_bytes: 1024 * 1024,
        h3_udp_socket_buffer_bytes: 4 * 1024 * 1024,
        client_active_ttl_secs: 180,
        udp_nat_idle_timeout_secs: 120,
        udp_max_concurrent_relay_tasks: 1_024,
    };

    /// Balanced profile for typical deployments.
    pub const MEDIUM: Self = Self {
        h2_stream_window_bytes: 4 * 1024 * 1024,
        h2_connection_window_bytes: 16 * 1024 * 1024,
        h2_max_send_buf_size: 4 * 1024 * 1024,
        h3_stream_window_bytes: 4 * 1024 * 1024,
        h3_connection_window_bytes: 16 * 1024 * 1024,
        h3_max_concurrent_bidi_streams: 1_024,
        h3_max_concurrent_uni_streams: 512,
        h3_write_buffer_bytes: 256 * 1024,
        h3_max_backpressure_bytes: 4 * 1024 * 1024,
        h3_udp_socket_buffer_bytes: 8 * 1024 * 1024,
        client_active_ttl_secs: 300,
        udp_nat_idle_timeout_secs: 240,
        udp_max_concurrent_relay_tasks: 2_048,
    };

    /// Maximum-throughput profile for single-tenant, high-bandwidth-delay-product links.
    pub const LARGE: Self = Self {
        h2_stream_window_bytes: 16 * 1024 * 1024,
        h2_connection_window_bytes: 64 * 1024 * 1024,
        h2_max_send_buf_size: 16 * 1024 * 1024,
        h3_stream_window_bytes: 16 * 1024 * 1024,
        h3_connection_window_bytes: 64 * 1024 * 1024,
        h3_max_concurrent_bidi_streams: 4_096,
        h3_max_concurrent_uni_streams: 1_024,
        h3_write_buffer_bytes: 512 * 1024,
        h3_max_backpressure_bytes: 16 * 1024 * 1024,
        h3_udp_socket_buffer_bytes: 32 * 1024 * 1024,
        client_active_ttl_secs: 300,
        udp_nat_idle_timeout_secs: 300,
        udp_max_concurrent_relay_tasks: 4_096,
    };

    pub(super) fn validate(&self) -> Result<()> {
        if self.h2_stream_window_bytes == 0 {
            bail!("tuning.h2_stream_window_bytes must be > 0");
        }
        if self.h2_connection_window_bytes == 0 {
            bail!("tuning.h2_connection_window_bytes must be > 0");
        }
        if self.h2_max_send_buf_size == 0 {
            bail!("tuning.h2_max_send_buf_size must be > 0");
        }
        if self.h3_stream_window_bytes == 0 {
            bail!("tuning.h3_stream_window_bytes must be > 0");
        }
        if self.h3_connection_window_bytes == 0 {
            bail!("tuning.h3_connection_window_bytes must be > 0");
        }
        if self.h3_max_concurrent_bidi_streams == 0 {
            bail!("tuning.h3_max_concurrent_bidi_streams must be > 0");
        }
        if self.h3_max_concurrent_uni_streams == 0 {
            bail!("tuning.h3_max_concurrent_uni_streams must be > 0");
        }
        if self.h3_write_buffer_bytes == 0 {
            bail!("tuning.h3_write_buffer_bytes must be > 0");
        }
        if self.h3_max_backpressure_bytes == 0 {
            bail!("tuning.h3_max_backpressure_bytes must be > 0");
        }
        if self.h3_udp_socket_buffer_bytes == 0 {
            bail!("tuning.h3_udp_socket_buffer_bytes must be > 0");
        }

        // HTTP/2 and HTTP/3 both require stream ≤ connection flow-control
        // windows, otherwise a single stream can deadlock on the connection
        // window.
        if self.h2_stream_window_bytes > self.h2_connection_window_bytes {
            bail!(
                "tuning.h2_stream_window_bytes ({}) must not exceed h2_connection_window_bytes ({})",
                self.h2_stream_window_bytes,
                self.h2_connection_window_bytes,
            );
        }
        if self.h3_stream_window_bytes > self.h3_connection_window_bytes {
            bail!(
                "tuning.h3_stream_window_bytes ({}) must not exceed h3_connection_window_bytes ({})",
                self.h3_stream_window_bytes,
                self.h3_connection_window_bytes,
            );
        }

        // `quinn` encodes QUIC flow-control windows as VarInt from u32, so
        // anything wider would panic at runtime.
        if self.h3_stream_window_bytes > u32::MAX as u64 {
            bail!("tuning.h3_stream_window_bytes must fit in u32 (max {})", u32::MAX);
        }
        if self.h3_connection_window_bytes > u32::MAX as u64 {
            bail!("tuning.h3_connection_window_bytes must fit in u32 (max {})", u32::MAX);
        }

        // UDP receive buffer must hold at least one max-size datagram.
        const MIN_UDP_BUFFER: usize = 64 * 1024;
        if self.h3_udp_socket_buffer_bytes < MIN_UDP_BUFFER {
            bail!(
                "tuning.h3_udp_socket_buffer_bytes ({}) must be at least {} bytes",
                self.h3_udp_socket_buffer_bytes,
                MIN_UDP_BUFFER,
            );
        }

        if self.client_active_ttl_secs == 0 {
            bail!("tuning.client_active_ttl_secs must be > 0");
        }
        if self.udp_nat_idle_timeout_secs == 0 {
            bail!("tuning.udp_nat_idle_timeout_secs must be > 0");
        }
        // `udp_max_concurrent_relay_tasks == 0` is a valid opt-out.

        Ok(())
    }

    pub(super) fn apply_overrides(&mut self, o: &TuningOverrides) {
        if let Some(v) = o.h2_stream_window_bytes {
            self.h2_stream_window_bytes = v;
        }
        if let Some(v) = o.h2_connection_window_bytes {
            self.h2_connection_window_bytes = v;
        }
        if let Some(v) = o.h2_max_send_buf_size {
            self.h2_max_send_buf_size = v;
        }
        if let Some(v) = o.h3_stream_window_bytes {
            self.h3_stream_window_bytes = v;
        }
        if let Some(v) = o.h3_connection_window_bytes {
            self.h3_connection_window_bytes = v;
        }
        if let Some(v) = o.h3_max_concurrent_bidi_streams {
            self.h3_max_concurrent_bidi_streams = v;
        }
        if let Some(v) = o.h3_max_concurrent_uni_streams {
            self.h3_max_concurrent_uni_streams = v;
        }
        if let Some(v) = o.h3_write_buffer_bytes {
            self.h3_write_buffer_bytes = v;
        }
        if let Some(v) = o.h3_max_backpressure_bytes {
            self.h3_max_backpressure_bytes = v;
        }
        if let Some(v) = o.h3_udp_socket_buffer_bytes {
            self.h3_udp_socket_buffer_bytes = v;
        }
        if let Some(v) = o.client_active_ttl_secs {
            self.client_active_ttl_secs = v;
        }
        if let Some(v) = o.udp_nat_idle_timeout_secs {
            self.udp_nat_idle_timeout_secs = v;
        }
        if let Some(v) = o.udp_max_concurrent_relay_tasks {
            self.udp_max_concurrent_relay_tasks = v;
        }
    }
}

impl Default for TuningProfile {
    fn default() -> Self {
        Self::LARGE
    }
}

/// Per-field overrides for [`TuningProfile`], parsed from the `[tuning]`
/// section of the config file. Any field left `None` is inherited from the
/// selected `tuning_profile` preset.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuningOverrides {
    #[serde(default)]
    pub h2_stream_window_bytes: Option<u32>,
    #[serde(default)]
    pub h2_connection_window_bytes: Option<u32>,
    #[serde(default)]
    pub h2_max_send_buf_size: Option<usize>,
    #[serde(default)]
    pub h3_stream_window_bytes: Option<u64>,
    #[serde(default)]
    pub h3_connection_window_bytes: Option<u64>,
    #[serde(default)]
    pub h3_max_concurrent_bidi_streams: Option<u32>,
    #[serde(default)]
    pub h3_max_concurrent_uni_streams: Option<u32>,
    #[serde(default)]
    pub h3_write_buffer_bytes: Option<usize>,
    #[serde(default)]
    pub h3_max_backpressure_bytes: Option<usize>,
    #[serde(default)]
    pub h3_udp_socket_buffer_bytes: Option<usize>,
    #[serde(default)]
    pub client_active_ttl_secs: Option<u64>,
    #[serde(default)]
    pub udp_nat_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub udp_max_concurrent_relay_tasks: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::{TuningOverrides, TuningPreset, TuningProfile};

    #[test]
    fn overrides_apply_on_top_of_preset() {
        let mut tuning = TuningPreset::Medium.preset();
        tuning.apply_overrides(&TuningOverrides {
            h3_udp_socket_buffer_bytes: Some(2 * 1024 * 1024),
            h3_max_concurrent_bidi_streams: Some(128),
            ..TuningOverrides::default()
        });
        assert_eq!(tuning.h3_udp_socket_buffer_bytes, 2 * 1024 * 1024);
        assert_eq!(tuning.h3_max_concurrent_bidi_streams, 128);
        assert_eq!(
            tuning.h3_connection_window_bytes,
            TuningProfile::MEDIUM.h3_connection_window_bytes,
        );
    }

    #[test]
    fn rejects_stream_window_above_connection_window() {
        let mut tuning = TuningProfile::LARGE;
        tuning.h3_stream_window_bytes = tuning.h3_connection_window_bytes + 1;
        let error = tuning.validate().unwrap_err().to_string();
        assert!(error.contains("h3_stream_window_bytes"));
        assert!(error.contains("must not exceed"));
    }

    #[test]
    fn rejects_zero_udp_socket_buffer() {
        let mut tuning = TuningProfile::LARGE;
        tuning.h3_udp_socket_buffer_bytes = 0;
        let error = tuning.validate().unwrap_err().to_string();
        assert!(error.contains("h3_udp_socket_buffer_bytes"));
    }

    #[test]
    fn rejects_oversized_h3_connection_window() {
        let mut tuning = TuningProfile::LARGE;
        tuning.h3_connection_window_bytes = (u32::MAX as u64) + 1;
        let error = tuning.validate().unwrap_err().to_string();
        assert!(error.contains("h3_connection_window_bytes"));
    }
}
