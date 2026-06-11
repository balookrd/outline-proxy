use anyhow::{Context, Result};
use rand::RngCore;
use socks5_proto::TargetAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct Ss2022TcpWriterState {
    pub request_salt: [u8; 32],
    pub header_sent: bool,
}

pub(super) fn unix_timestamp_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

pub(super) fn build_ss2022_request_header(target: &TargetAddr) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut padding = [0u8; 16];
    rand::rng().fill_bytes(&mut padding);
    outline_wire::ss2022::build_request_header(target, unix_timestamp_secs()?, &padding)
        .map_err(Into::into)
}
