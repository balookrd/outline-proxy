use anyhow::Result;

/// Parse a VLESS UUID in hex/dashed form into 16 raw bytes.
pub fn parse_uuid(input: &str) -> Result<[u8; 16]> {
    outline_wire::vless::parse_uuid(input)
        .map_err(|_| anyhow::anyhow!("invalid vless uuid: {input}"))
}
