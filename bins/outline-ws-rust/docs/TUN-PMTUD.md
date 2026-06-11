# TUN UDP Path-MTU Discovery

How the TUN UDP engine handles datagrams the upstream transport refuses
for being too large, and the safety net that keeps it from blackholing
QUIC for legitimate clients.

*Russian version: [TUN-PMTUD.ru.md](TUN-PMTUD.ru.md)*

---

## When this fires

For every TUN-ingested UDP flow that resolves to a tunnel uplink, the
engine wraps the payload in SOCKS5 framing and hands it to the
transport's `send_packet`. Several transports refuse oversized payloads
they cannot fragment around:

- raw QUIC SS-UDP — `QuicDatagramChannel` bounded by the negotiated
  `max_datagram_size` (typically ~1180 bytes);
- VLESS QUIC UDP — the same QUIC datagram budget plus 4-byte session-id
  overhead;
- VLESS-UDP framing — hard 64 KiB ceiling on the length-prefixed frame;
- Shadowsocks 2022 UDP — refuses anything that exceeds the AEAD record
  limit on the uplink leg.

A refusal surfaces as `OversizedUdpDatagram { transport, payload_len,
limit }` or `Ss2022Error::OversizedUdpUplink`. The TUN engine detects
both via `is_dropped_oversized_udp_error` and routes the failure to
the PMTUD path instead of treating it as an uplink failure.

## Why we send an ICMP signal

The transport drop is invisible to the client: the sender keeps
retransmitting the same too-large payload on every loss timer. Without
an in-band signal it never learns the effective tunnel MTU. Real
production breakage came from VoWiFi IKE_AUTH carrying client
certificates over a raw-QUIC uplink — the IKE retransmits piled up,
the certificate exchange never completed, and the call failed.

The fix is to synthesise an ICMP error toward the original sender so
its own PMTUD state machine reacts:

- **IPv4** — `Destination Unreachable / Fragmentation Needed` (Type 3 /
  Code 4) with the advertised Next-Hop MTU in the second word of the
  ICMP header (RFC 1191).
- **IPv6** — `Packet Too Big` (Type 2 / Code 0) with the advertised MTU
  in the second word (RFC 4443 §3.2).

The reply quotes the original IP header and UDP header (8 bytes of
upper-layer data) so the sender's stack can match it back to the
offending socket, per RFC 1812 §4.3.2.3 and RFC 4443 §3.2.

## Advertised Next-Hop MTU

The transport-reported `limit` (bytes the transport will accept for the
SOCKS5-wrapped payload) is passed through to the ICMP advertised MTU,
clamped to each family's protocol minimum:

- IPv4: clamped to `IPV4_MIN_PATH_MTU = 576` (RFC 791);
- IPv6: clamped to `IPV6_MIN_PATH_MTU = 1280` (RFC 8200).

The ICMPv6 PTB payload itself is truncated so the final packet does not
exceed the IPv6 minimum link MTU, per RFC 4443 §2.4(c).

## Throttle

Each flow is allowed one PTB per second, matching the Linux
`net.ipv4.icmp_ratelimit` default. RFC 4443 §2.4(f) makes rate-limiting
mandatory for ICMPv6; RFC 1812 §4.3.2.8 strongly recommends it for
IPv4. Bursts of oversize retransmits therefore produce one PTB per
second per flow — enough for any reasonable PMTUD state machine to
react, but small enough that a misbehaving sender cannot trigger an
ICMP storm out of the TUN interface.

The throttle state lives on the flow's `last_ptb_sent` timestamp, so
once a flow is evicted from the table the PTB budget resets with it.
For a flow that has just been evicted but is still racing the cleanup
path, the throttle conservatively returns "suppress" — better a missed
PTB than an unbounded one during teardown.

## QUIC floor — why we sometimes stay silent

A PTB advertising a path MTU below QUIC's own Initial-datagram floor is
a problem rather than a fix. RFC 9000 §14.1 requires QUIC v1 endpoints
to send UDP datagrams carrying Initial packets at least **1200 bytes**
in the UDP payload (IPv6 endpoints additionally honour the 1280-byte
minimum link MTU). A compliant stack that receives an ICMP error
claiming the path MTU is below that floor concludes the destination
cannot carry QUIC at all — and disables QUIC for the destination,
falling back to TCP.

That is the opposite of what an operator carrying real QUIC traffic
wants. The motivating regression: Samsung Smart-TV YouTube clients
shipped QUIC Initial datagrams of 1200 bytes through the TUN to
googlevideo. The SS-over-QUIC datagram channel surfaced
`OversizedUdpDatagram { limit ≈ 1180 }` for the framed payload, the
engine synthesised a PTB advertising 1180 bytes, and the TV's QUIC
stack promptly disabled HTTP/3 for googlevideo. The session stayed on
TCP forever, and dashboards showed UDP traffic vanish from the uplink.

The engine therefore suppresses the PTB entirely when the transport
limit sits below QUIC's family-specific floor:

| IP family | Floor (bytes) | Source                                          |
| --------- | ------------- | ----------------------------------------------- |
| IPv4      | 1200          | RFC 9000 §14.1 minimum Initial UDP payload       |
| IPv6      | 1280          | RFC 9000 §14.1 + RFC 8200 minimum link MTU       |

Below the floor the oversize drop falls back to its pre-PMTUD
behaviour: the engine silently drops the datagram, the sender retries
or times out on its own schedule, and clients keep their QUIC state
intact. Above the floor — the entire ~1300–1450 byte range where real
PMTUD breakage lives — the PTB still goes out unchanged.

`limit == None` (the transport refused without surfacing a specific
size) is treated as permissive: suppressing in that case would mute
legitimate PMTUD signals on transports that simply do not report a
size. The protocol-minimum clamps in the ICMP builders (576 v4 / 1280
v6) still apply, so the wire-level advertisement is always well-formed.

## What an operator sees

Counters and dashboards remain the source of truth for diagnosing
oversize behaviour:

- `outline_ws_rust_udp_oversized_dropped_total{direction, cause}` —
  every oversize drop, broken down by cause (`quic_dgram`,
  `vless_quic_dgram`, `vless_udp`, `ss_socket`, …). A spike with no
  matching PTB on the wire means the QUIC-floor gate is keeping a
  client out of TCP fallback.
- `outline_ws_rust_tun_packet_total{direction="upstream_to_tun"}` —
  any synthesised PTB shows up here as one accepted upstream-to-TUN
  packet per emission.

A QUIC stack that does accept the PTB and lowers its path MTU will
typically also re-emit Initial datagrams of the new size; if those
still oversize the transport the loop is self-throttled by the
1 PTB / sec / flow limit and visible as a steady, low-rate
`quic_dgram` drop series.

## Tuning surface

The QUIC Initial-datagram minimum itself is a protocol-level constant
baked into RFC 9000 and not negotiable per-deployment. The single
operator-visible knob is whether the engine may emit PTBs that
advertise a path MTU below that minimum:

```toml
[tun]
# Default: false. PTBs whose advertised path MTU would sit below QUIC
# v1's Initial-datagram minimum (1200 v4 / 1280 v6) are suppressed,
# keeping compliant QUIC clients on UDP.
pmtud_emit_below_quic_initial = false
```

Setting `pmtud_emit_below_quic_initial = true` restores unconditional
PTB emission for every oversize drop that has a known transport limit
(`None` limits remain permissive under both settings — see
`should_emit_ptb_for_limit`). Use it on deployments where QUIC
eviction is a non-issue and the explicit PMTUD signal on every drop
is worth more: pure VoWiFi / IKEv2 concentrators carrying IKE_AUTH
with certificates over a narrow raw-QUIC uplink are the canonical
example — the PTB is the only signal that lets the IKE retransmit
loop learn the effective tunnel MTU before the call times out.

The trade-off:

| Setting | `quic_dgram` sub-minimum drops           | VoWiFi / IKE convergence on narrow uplinks |
| ------- | ---------------------------------------- | ------------------------------------------- |
| `false` | silent (sender retries on its own clock) | slower (no in-band MTU hint)                |
| `true`  | one PTB / sec / flow                     | fast (PMTUD reacts immediately)             |

The throttle, builders, and protocol-minimum clamps (576 v4 / 1280 v6
in the ICMP header itself) all apply unchanged under either setting.

If an operator wants to disable PMTUD synthesis altogether (mirror the
pre-bcaf86d behaviour exactly), the upstream transport's reported
limit remains the only handle: a transport that does not surface
`OversizedUdpDatagram` skips the PMTUD path entirely.

## References

- RFC 791 §3.1 — IPv4 minimum datagram size (576 bytes)
- RFC 1191 — IPv4 Path MTU Discovery
- RFC 1812 §4.3.2.3, §4.3.2.8 — ICMP error quoting and rate limiting
- RFC 4443 §2.4(c), §2.4(f), §3.2 — ICMPv6 error message rules
- RFC 8200 §5 — IPv6 minimum link MTU (1280 bytes)
- RFC 9000 §14.1, §14.2.1 — QUIC datagram size and ICMP handling
- RFC 9221 — Unreliable Datagram Extension for QUIC
