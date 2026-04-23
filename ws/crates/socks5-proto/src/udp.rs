use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Result, Socks5Error};
use crate::target::TargetAddr;

pub struct Socks5UdpPacket<'a> {
    pub fragment: u8,
    pub target: TargetAddr,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5UdpTcpPacket {
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

pub fn parse_udp_request(packet: &[u8]) -> Result<Socks5UdpPacket<'_>> {
    if packet.len() < 4 {
        return Err(Socks5Error::UdpPacketTooShort);
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(Socks5Error::InvalidUdpReservedBytes);
    }
    let fragment = packet[2];
    let (target, consumed) = TargetAddr::from_wire_bytes(&packet[3..])?;
    let payload_offset = 3 + consumed;
    Ok(Socks5UdpPacket {
        fragment,
        target,
        payload: &packet[payload_offset..],
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

    let mut addr_buf = vec![0u8; addr_len];
    reader
        .read_exact(&mut addr_buf)
        .await
        .map_err(Socks5Error::io("reading UDP-in-TCP target address"))?;
    let (target, consumed) = TargetAddr::from_wire_bytes(&addr_buf)?;
    if consumed != addr_len {
        return Err(Socks5Error::UdpInTcpHeaderMismatch);
    }

    let mut payload = vec![0u8; data_len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(Socks5Error::io("reading UDP-in-TCP payload"))?;

    Ok(Some(Socks5UdpTcpPacket { target, payload }))
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
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn socks5_udp_packet_round_trip() {
        let target = TargetAddr::IpV4(Ipv4Addr::new(1, 1, 1, 1), 53);
        let packet = build_udp_packet(&target, b"hello").unwrap();
        let parsed = parse_udp_request(&packet).unwrap();
        assert_eq!(parsed.fragment, 0);
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.payload, b"hello");
    }

    #[tokio::test]
    async fn socks5_udp_in_tcp_packet_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let target = TargetAddr::Domain("example.com".to_string(), 53);

        let send = tokio::spawn(async move {
            write_udp_tcp_packet(&mut writer, &target, b"hello").await.unwrap();
        });

        let packet = read_udp_tcp_packet(&mut reader).await.unwrap().unwrap();
        send.await.unwrap();
        assert_eq!(packet.target, TargetAddr::Domain("example.com".to_string(), 53));
        assert_eq!(packet.payload, b"hello");
    }
}
