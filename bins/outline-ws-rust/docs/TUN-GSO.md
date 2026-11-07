# TUN GSO / GRO / USO offload (`[tun] gso`, `[tun] gro`, `[tun] uso`)

This document describes the three TUN offload settings of `outline-ws-rust` on Linux: what each one changes on the read and write paths, how to check that it is active, and how to roll it back. It is for operators running the TUN client on Linux.

*Русская версия: [TUN-GSO.ru.md](TUN-GSO.ru.md)*

## Per-packet cost without offload

The TUN client terminates TCP in userspace. Without offload, every downlink segment is written to the TUN device with a separate `write(2)`, and every uplink segment arrives with a separate `read(2)`. On a busy link that is thousands of syscalls per second, and each packet goes through the full kernel networking path (routing, `nftables`, `conntrack`, and per-packet WireGuard encryption when the client sits behind WireGuard) before it reaches the NIC or our stack. A profile of a live client at about 40–60 Mbit/s showed CPU spent mostly in this per-packet kernel work (`nft_do_chain`, `nf_conntrack_*`, `fib_*`, `tun_get_user`, `wg_xmit`), not in crypto or the userspace stack, with `write(2)` the most frequent syscall.

Offload batches packets so the kernel path and our stack run once per super-packet instead of once per MSS:

| Key | Direction | Mechanism |
|---|---|---|
| `gso` | downlink, write (TSO) | We hand the kernel one TCP super-segment of up to 61 440 bytes instead of N MSS packets; the kernel splits it per MSS after routing / `nftables` / `conntrack` / WireGuard ran once |
| `gro` | uplink, read (GRO) | The kernel coalesces several inbound MSS segments of one flow into one super-packet (up to 64 KiB) and hands it to us whole, so read / parse / TCP work runs once |
| `uso` | downlink UDP, write (USO) | We hand the kernel one `GSO_UDP_L4` super-segment of equal-sized datagrams; the kernel splits it per datagram |

## What `gso = true` does

- Opens the TUN device with `IFF_VNET_HDR`, so every `read(2)` / `write(2)` carries a 10-byte `virtio_net_hdr` prefix.
- Downlink (write): `flush` coalesces queued server→client data into one TCP super-segment (up to 61 440 bytes, `GSO_MAX_SUPER_SEGMENT_PAYLOAD`) with a `virtio_net_hdr` that sets the MSS (`gso_size`) and a partial (pseudo-header) checksum. The kernel splits it into MSS segments, fills in each segment's sequence number and finalises its L4 checksum. This is where the downlink CPU saving comes from.
- Retransmits stay per MSS: the send scoreboard tracks each MSS segment separately, so a loss inside a super-segment is recovered by resending one MSS packet, the same as without GSO.
- `gso` alone does not call `TUNSETOFFLOAD`, so the read path is unchanged; the uplink is covered by `gro`.

## What `gro = true` does

Requires `gso`; `gro = true` with `gso = false` is a config error (`tun.gro requires tun.gso`).

- Calls `TUNSETOFFLOAD` with `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6`, so the kernel may coalesce inbound TCP into GRO super-packets (up to 64 KiB, `gso_type` TCPV4/6) instead of segmenting to ≤ MSS.
- Uplink (read): the read loop passes the oversized TCP segment straight to the userspace TCP engine. Its receive path already accepts segments larger than one MSS: it takes the size from the IP total length, buffers as `Bytes` and trims to the receive window. `TUN_F_CSUM` also enables RX checksum offload, so the kernel may leave the L4 checksum unfinalised; the read loop recomputes it from the payload.
- UDP stays per datagram under `gro` alone: `TUN_F_USO4/6` is not requested, so without `NETIF_F_GSO_UDP_L4` the kernel splits UDP GRO back into datagrams before we read them. If a UDP super-packet arrives anyway, the read loop splits it back into datagrams.
- Coalescing happens only on bursts: GRO merges segments only when the source bursts (bulk upload, or a forwarding path with `generic-receive-offload` on the inbound NIC). ACK-only and interactive uplink stays per packet.
- If the kernel rejects `TUNSETOFFLOAD`, the client logs a `WARN` (`TUNSETOFFLOAD failed; TUN offload state may be stale`) and continues without GRO; write-side TSO keeps working.

## What `uso = true` does

Requires `gso`; `uso = true` with `gso = false` is a config error (`tun.uso requires tun.gso`).

- Calls `TUNSETOFFLOAD` with `TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6`, so the writer can hand the kernel one `GSO_UDP_L4` super-segment (at most 64 datagrams, `UDP_MAX_SEGMENTS`, and at most 61 440 bytes of payload) that the kernel splits into equal `gso_size` datagrams. This is the UDP counterpart of `gso`'s TCP TSO on the write path.
- Downlink (write): the per-flow reader coalesces consecutive equal-sized datagrams of one flow (the 4-tuple is fixed, so all go to the same destination) into one super-segment with a partial (pseudo-header) checksum that the kernel finalises per datagram. A datagram of another size ends the batch and starts the next one; no datagram is dropped. The saving is largest for bulk QUIC video, where downlink is the heavy UDP direction.
- `TUN_F_USO` also enables RX UDP GRO: the kernel may hand us coalesced UDP super-packets on read, and the read loop splits them back into datagrams (`resegment_udp_gso`).
- `TUN_F_CSUM` (mandatory for USO) enables RX checksum offload; the read loop recomputes any unfinalised checksum.
- If the kernel rejects USO (kernel < 6.2), the client logs `TUNSETOFFLOAD rejected USO; UDP GSO disabled, TCP offload kept` and keeps TCP offload.

## Enabling

All three are on by default: `gso` defaults to `true`, `gro` and `uso` default to the value of `gso`.

```toml
[tun]
gso = true   # downlink TSO (default)
gro = true   # uplink GRO (default: follows gso)
uso = true   # downlink UDP USO (default: follows gso)
```

Linux only; ignored on other targets. Requirements:

- `gso` needs a kernel with `IFF_VNET_HDR`. If `TUNSETIFF` with `IFF_VNET_HDR` fails, the client attaches without it, logs `TUNSETIFF with IFF_VNET_HDR failed; attached without it — TUN GSO/GRO/USO disabled`, and uses the per-packet path.
- `gro` and `uso` need `TUNSETOFFLOAD`; `uso` needs `TUN_F_USO` (kernel ≥ 6.2). A rejected offload is logged and the rest is kept.
- `gro` and `uso` can be set independently of each other, but each requires `gso = true`.

## Verification

All three paths are in the data plane, so check data integrity first, then CPU:

1. Set the keys and restart the client.
2. Downlink (`gso`): download a large file through the tunnel and compare its `sha256sum` with the original. The hashes must match.
3. Uplink (`gro`): upload a large file through the tunnel and compare its `sha256sum` on the far end.
4. UDP (`uso`): check that DNS resolves and QUIC traffic (for example YouTube) plays, then run a bulk UDP transfer. A growing `outline_ws_tun_packets_total{outcome="uso_supersegment"}` means downlink datagrams are being coalesced.
5. Compare CPU and syscall rate with offload off at the same throughput: `sudo timeout 5 strace -f -c -p $(pidof outline-ws-rust)`. With `gso` the `write` count drops; with `gro` on a bulk upload the `read` count drops.

The startup log lines `TUN offload negotiated` (fields `req_gso`, `req_gro`, `req_uso`, `vnet_hdr`, `rx_gro`, `udp_gso`) and `TUN loop started` (fields `gso`, `rx_gro`, `udp_gso`) show what the kernel accepted.

Reading offload state with `ethtool -k <tun>`:

- `gso` (write-side TSO) is not visible in `ethtool`. It works through the per-`read`/`write` `virtio_net_hdr` on the fd opened with `IFF_VNET_HDR`; that is a queue property, not a netdevice feature. The log lines above are the only confirmation.
- `gro` and `uso` are visible, because `TUNSETOFFLOAD` sets real netdevice features. With both on, these should read `on`: `tx-checksum-ip-generic` (`TUN_F_CSUM`), `tx-tcp-segmentation` and `tx-tcp6-segmentation` (`gro`, `TUN_F_TSO4/6`), `tx-udp-segmentation` (`uso`, `TUN_F_USO4/6`). A working `uso` shows `tx-udp-segmentation: on` without a trailing `[requested on]`; the `[requested on]` form is the stuck state described in [Known problems](#known-problems).
- `generic-segmentation-offload` and `generic-receive-offload` are the kernel's own software GSO/GRO for the device and are not set by the client; ignore them.

## Rollback

- `gso = false` restores the per-packet path; `gro` and `uso` follow it unless set explicitly (setting either to `true` with `gso = false` fails config load). No rebuild is needed, only a restart.
- `gro = false` drops only uplink GRO; downlink TSO stays.
- **Warning:** do not set `uso = false` while `gso = true`. With `IFF_VNET_HDR` the kernel frames local UDP-GSO (QUIC/HTTP3 egress of applications on the host) as `GSO_UDP_L4` super-packets, which arrive intact only when `TUN_F_USO` is on. `gso` without `uso` breaks UDP through the tunnel. Use `uso = false` only as a diagnostic step, together with `gso = false` to roll back.

## Known problems

`TUNSETOFFLOAD` sets feature flags on the device, and on a persistent TUN interface they survive a process restart. The client sets the offload state explicitly on every attach (including `0` when disabled), so a restart normally applies the new config. If after a restart `ethtool -k <tun>` shows `tx-udp-segmentation: off [requested on]`, force a real feature transition with `ethtool -K <tun> tx-udp-segmentation off` and restart the client, or recreate the interface (`ip link del` / `ip tuntap add`).
