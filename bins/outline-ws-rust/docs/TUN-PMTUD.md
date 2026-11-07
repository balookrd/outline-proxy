# TUN UDP path-MTU discovery

This document describes how the TUN UDP engine of `outline-ws-rust` (`crates/outline-tun`) handles datagrams that the upstream transport refuses as too large: when it sends an ICMP "packet too big" signal to the sender, what MTU it advertises, and when it stays silent so QUIC clients do not fall back to TCP. It is for operators of the TUN client and developers of the UDP data path.

*Russian version: [TUN-PMTUD.ru.md](TUN-PMTUD.ru.md)*

## When the PMTUD path runs

For every UDP flow read from the TUN device and routed to a tunnel uplink, the engine wraps the payload in SOCKS5 UDP framing and passes it to the transport's `send_packet`. Some transports refuse payloads above a hard limit:

| Transport | Limit | Error |
|---|---|---|
| VLESS-UDP | 65 536 bytes of payload (`MAX_VLESS_UDP_PAYLOAD`) | `OversizedUdpDatagram { transport: "vless-udp", payload_len, limit }` |
| Shadowsocks UDP over a plain UDP socket (`UdpWsTransport::from_socket`) | 65 507 bytes (`MAX_UDP_SOCKET_PACKET_SIZE`) | `Ss2022Error::OversizedUdpUplink` (carries no limit) |

The engine detects both errors with `is_dropped_oversized_udp_error` and sends the failure to the PMTUD path instead of treating it as an uplink failure.

UDP over HTTP/3 datagrams does not reach this path: a packet that does not fit the current datagram size is sent on the stream instead and counted on `outline_ws_udp_h3_datagram_fallback_total{reason="too_large"}`.

## Why the engine sends an ICMP signal

The transport drop is invisible to the sender: it keeps retransmitting the same oversized payload on every loss timer and never learns the effective tunnel MTU. In production this broke VoWiFi: IKE_AUTH with client certificates over a tunnel uplink was retransmitted until the certificate exchange timed out and the call failed.

The engine therefore synthesises an ICMP error toward the original sender so that the sender's own PMTUD reacts:

- IPv4: `Destination Unreachable / Fragmentation Needed` (Type 3 / Code 4) with the Next-Hop MTU in the second word of the ICMP header (RFC 1191).
- IPv6: `Packet Too Big` (Type 2 / Code 0) with the MTU in the second word (RFC 4443 §3.2).

The reply quotes the original IP header and the 8-byte UDP header, so the sender's stack can match it to the socket (RFC 1812 §4.3.2.3, RFC 4443 §3.2). The quoted header is rebuilt from the flow key (`build_ipv4_udp_packet` / `build_ipv6_udp_packet` with an empty payload).

## Advertised MTU

The transport's `limit` (bytes it accepts for the SOCKS5-wrapped payload) becomes the advertised MTU, raised to the family's protocol minimum:

| Family | Minimum | Constant |
|---|---|---|
| IPv4 | 576 (RFC 791) | `IPV4_MIN_PATH_MTU` |
| IPv6 | 1280 (RFC 8200) | `IPV6_MIN_PATH_MTU` |

When the error carries no limit (`Ss2022Error::OversizedUdpUplink`), the advertised MTU is the family minimum. A limit that does not fit the header field (for example VLESS-UDP's 65 536 in the 16-bit IPv4 field) is capped at the field's maximum.

The ICMPv6 Packet Too Big payload is truncated so the whole packet does not exceed the IPv6 minimum link MTU (RFC 4443 §2.4(c)).

## Rate limit

Each flow gets at most one PTB per second (`PTB_THROTTLE`, the same as the Linux `net.ipv4.icmp_ratelimit` default of 1000 ms). RFC 4443 §2.4(f) requires rate limiting for ICMPv6; RFC 1812 §4.3.2.8 recommends it for IPv4. A burst of oversized retransmits therefore produces one PTB per second per flow, so a misbehaving sender cannot make the TUN interface emit an ICMP storm.

The throttle state is the flow's `last_ptb_sent` timestamp, so it is reset when the flow is evicted from the table. If the flow is already gone from the table when the PTB would be sent (it is being torn down), no PTB is sent.

## QUIC floor: when the engine stays silent

A PTB that advertises a path MTU below QUIC's Initial datagram minimum makes things worse. RFC 9000 §14.1 requires QUIC v1 endpoints to send Initial packets in UDP datagrams with at least 1200 bytes of UDP payload (IPv6 endpoints also observe the 1280-byte minimum link MTU). A compliant stack that gets an ICMP error claiming a smaller path MTU concludes that the destination cannot carry QUIC, disables QUIC for it and falls back to TCP.

The regression that introduced the check: Samsung Smart TV YouTube clients sent 1200-byte QUIC Initial datagrams through the TUN to googlevideo. The SS-over-QUIC datagram carrier (since removed) reported `OversizedUdpDatagram { limit ≈ 1180 }` for the framed payload, the engine sent a PTB advertising 1180 bytes, and the TV's QUIC stack disabled HTTP/3 for googlevideo. The sessions stayed on TCP, and UDP traffic disappeared from the uplink.

The engine therefore sends no PTB when the transport limit is below the family's QUIC floor (`should_emit_ptb_for_limit`):

| IP family | Floor (bytes) | Constant | Source |
|---|---|---|---|
| IPv4 | 1200 | `QUIC_MIN_INITIAL_PAYLOAD_V4` | RFC 9000 §14.1 minimum Initial UDP payload |
| IPv6 | 1280 | `QUIC_MIN_INITIAL_PAYLOAD_V6` | RFC 9000 §14.1 + RFC 8200 minimum link MTU |

Below the floor the datagram is dropped silently, as before PMTUD existed: the sender retries or times out on its own schedule and keeps its QUIC state. At or above the floor (including the ~1300–1450 byte range where path MTU problems usually are) the PTB is sent.

An error without a limit (`limit == None`) always gets a PTB: without a reported size the engine cannot show that the floor is violated, and suppressing would hide PMTUD signals on transports that do not report a size. The advertised MTU is then the family minimum (576 / 1280).

Of the current transports only VLESS-UDP reports a limit (65 536 bytes, above both floors), so the floor check does not suppress anything on current carriers; it applies to any transport that reports a smaller limit.

## Diagnostics

- `outline_ws_udp_oversized_dropped_total{direction, cause}` counts every oversize drop. `cause` values: `vless_udp`, `ss_socket`, `xhttp_records`, `socks_client`, `socks_relay`, `socks_direct`, `socks_in_tcp`. The two causes that feed the TUN PMTUD path are `vless_udp` and `ss_socket`.
- `outline_ws_udp_h3_datagram_fallback_total{reason="too_large"}` counts HTTP/3 datagrams that did not fit and went on the stream.
- There is no counter for emitted PTBs: `write_pmtud_packet` writes the ICMP packet to the TUN device without recording a metric. A failed PTB write is logged at `DEBUG` (`failed to emit ICMP PTB after TUN UDP oversize drop`).

A QUIC stack that accepts the PTB and lowers its path MTU usually resends Initial datagrams at the new size. If those are still too large for the transport, the loop is limited to one PTB per second per flow and shows up as a steady low-rate series of oversize drops.

## Configuration

The QUIC Initial minimum is fixed by RFC 9000. The one setting is whether the engine may send PTBs that advertise a path MTU below that minimum:

```toml
[tun]
# Default: false. PTBs whose advertised path MTU would sit below QUIC
# v1's Initial-datagram minimum (1200 v4 / 1280 v6) are suppressed,
# keeping compliant QUIC clients on UDP.
pmtud_emit_below_quic_initial = false
```

| Key | Default | What it does | When to change |
|---|---|---|---|
| `pmtud_emit_below_quic_initial` | `false` | `true` sends a PTB for every oversize drop with a known limit, including limits below the QUIC floor. Errors without a limit get a PTB under both settings | Set `true` on hosts without QUIC clients where the PMTUD signal matters more, for example VoWiFi / IKEv2 with certificate-bearing IKE_AUTH over a narrow tunnel uplink: the PTB lets IKE learn the tunnel MTU before the call times out |

Effect of the setting on sub-floor drops:

| Setting | Sub-floor drops | VoWiFi / IKE on narrow uplinks |
|---|---|---|
| `false` | Silent; the sender retries on its own timer | Slower: no in-band MTU hint |
| `true` | One PTB per second per flow | PMTUD reacts on the first PTB |

The rate limit, the ICMP builders and the protocol-minimum clamps (576 / 1280 in the ICMP header) work the same under both settings.

There is no setting that disables PTB synthesis entirely (the behaviour before commit `bcaf86d`). A transport that does not raise `OversizedUdpDatagram` or `Ss2022Error::OversizedUdpUplink` never enters the PMTUD path.

## References

- RFC 791 §3.1: IPv4 minimum datagram size (576 bytes)
- RFC 1191: IPv4 Path MTU Discovery
- RFC 1812 §4.3.2.3, §4.3.2.8: ICMP error quoting and rate limiting
- RFC 4443 §2.4(c), §2.4(f), §3.2: ICMPv6 error message rules
- RFC 8200 §5: IPv6 minimum link MTU (1280 bytes)
- RFC 9000 §14.1, §14.2.1: QUIC datagram size and ICMP handling
- RFC 9221: Unreliable Datagram Extension for QUIC
