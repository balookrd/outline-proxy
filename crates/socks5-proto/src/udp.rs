use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Result, Socks5Error};
use crate::target::TargetAddr;

pub struct Socks5UdpPacket<'a> {
    pub fragment: u8,
    pub target: TargetAddr,
    /// The Shadowsocks UDP body `addr_wire || data` — the datagram with only the
    /// 3-byte RSV+FRAG prefix removed. Handed to the tunnel unchanged so the
    /// address is not re-serialised and the data is not copied.
    pub body: &'a [u8],
    /// The datagram data alone (`body` with the leading address removed), used
    /// by the policy-direct path which sends straight to the target socket.
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5UdpTcpPacket {
    pub target: TargetAddr,
    /// Shadowsocks UDP body `addr_wire || data`, read into one contiguous
    /// buffer so the tunnel send path forwards it without rebuilding.
    pub body: Vec<u8>,
    /// Length of the leading address in `body`; `body[addr_len..]` is the data.
    pub addr_len: usize,
}

pub fn parse_udp_request(packet: &[u8]) -> Result<Socks5UdpPacket<'_>> {
    if packet.len() < 4 {
        return Err(Socks5Error::UdpPacketTooShort);
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(Socks5Error::InvalidUdpReservedBytes);
    }
    let fragment = packet[2];
    let body = &packet[3..];
    let (target, consumed) = TargetAddr::from_wire_bytes(body)?;
    Ok(Socks5UdpPacket {
        fragment,
        target,
        body,
        payload: &body[consumed..],
    })
}

pub fn build_udp_packet(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8, 0u8, 0u8];
    out.extend_from_slice(&target.to_wire_bytes()?);
    out.extend_from_slice(payload);
    Ok(out)
}

pub async fn read_udp_tcp_packet<R>(reader: &mut R) -> Result<Option<Socks5UdpTcpPacket>>
where
    R: AsyncRead + Unpin,
{
    let mut data_len = [0u8; 2];
    let read = reader
        .read(&mut data_len[..1])
        .await
        .map_err(Socks5Error::io("reading UDP-in-TCP data length"))?;
    if read == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut data_len[1..])
        .await
        .map_err(Socks5Error::io("reading UDP-in-TCP data length tail"))?;
    let data_len = u16::from_be_bytes(data_len) as usize;

    let mut header_len = [0u8; 1];
    reader
        .read_exact(&mut header_len)
        .await
        .map_err(Socks5Error::io("reading UDP-in-TCP header length"))?;
    let header_len = header_len[0] as usize;
    let addr_len = header_len
        .checked_sub(3)
        .ok_or(Socks5Error::InvalidUdpInTcpHeaderLen(header_len as u16))?;

    // Read the address and the data into one contiguous `addr_wire || data`
    // buffer so the tunnel send path forwards it without a rebuild.
    let mut body = vec![0u8; addr_len + data_len];
    reader
        .read_exact(&mut body[..addr_len])
        .await
        .map_err(Socks5Error::io("reading UDP-in-TCP target address"))?;
    let (target, consumed) = TargetAddr::from_wire_bytes(&body[..addr_len])?;
    if consumed != addr_len {
        return Err(Socks5Error::UdpInTcpHeaderMismatch);
    }
    reader
        .read_exact(&mut body[addr_len..])
        .await
        .map_err(Socks5Error::io("reading UDP-in-TCP payload"))?;

    Ok(Some(Socks5UdpTcpPacket { target, body, addr_len }))
}

pub async fn write_udp_tcp_packet<W>(
    writer: &mut W,
    target: &TargetAddr,
    payload: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let addr = target.to_wire_bytes()?;
    let header_len = 3 + addr.len();
    let header_len: u8 = header_len
        .try_into()
        .map_err(|_| Socks5Error::UdpInTcpFrameTooLarge { field: "header" })?;
    let data_len: u16 = payload
        .len()
        .try_into()
        .map_err(|_| Socks5Error::UdpInTcpFrameTooLarge { field: "payload" })?;

    writer
        .write_all(&data_len.to_be_bytes())
        .await
        .map_err(Socks5Error::io("writing UDP-in-TCP data length"))?;
    writer
        .write_all(&[header_len])
        .await
        .map_err(Socks5Error::io("writing UDP-in-TCP header length"))?;
    writer
        .write_all(&addr)
        .await
        .map_err(Socks5Error::io("writing UDP-in-TCP target address"))?;
    writer
        .write_all(payload)
        .await
        .map_err(Socks5Error::io("writing UDP-in-TCP payload"))?;
    Ok(())
}

#[cfg(test)]
#[path = "tests/udp.rs"]
mod tests;
