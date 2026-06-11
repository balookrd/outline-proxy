use anyhow::{Result, bail};

/// Parse a VLESS UUID in hex/dashed form into 16 raw bytes.
pub fn parse_uuid(input: &str) -> Result<[u8; 16]> {
    let mut hex = [0_u8; 32];
    let mut len = 0;
    for byte in input.bytes() {
        if byte == b'-' {
            continue;
        }
        if len == hex.len() || !byte.is_ascii_hexdigit() {
            bail!("invalid vless uuid: {input}");
        }
        hex[len] = byte;
        len += 1;
    }
    if len != hex.len() {
        bail!("invalid vless uuid length: {input}");
    }
    let mut out = [0_u8; 16];
    for i in 0..16 {
        out[i] = (hex_val(hex[i * 2])? << 4) | hex_val(hex[i * 2 + 1])?;
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid vless uuid hex: {byte}"),
    }
}
