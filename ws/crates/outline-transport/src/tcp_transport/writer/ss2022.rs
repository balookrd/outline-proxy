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
    let target = target.to_wire_bytes()?;
    let padding_len: u16 = 16;
    let mut fixed = Vec::with_capacity(11);
    fixed.push(0);
    fixed.extend_from_slice(&unix_timestamp_secs()?.to_be_bytes());
    fixed.extend_from_slice(
        &(target.len() as u16 + 2 + usize::from(padding_len) as u16).to_be_bytes(),
    );

    let mut variable = Vec::with_capacity(target.len() + 2 + usize::from(padding_len));
    variable.extend_from_slice(&target);
    variable.extend_from_slice(&padding_len.to_be_bytes());
    let mut padding = vec![0u8; usize::from(padding_len)];
    rand::thread_rng().fill_bytes(&mut padding);
    variable.extend_from_slice(&padding);
    Ok((fixed, variable))
}
