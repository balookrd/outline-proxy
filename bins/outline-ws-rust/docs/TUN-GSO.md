# TUN GSO offload (`[tun] gso`)

*Русская версия: [TUN-GSO.ru.md](TUN-GSO.ru.md)*

## Why

The TUN client terminates TCP in userspace, so every downlink segment it
delivers to the client is written to the TUN device with a separate `write(2)`.
On a busy link that is thousands of writes per second, and each one traverses
the full kernel networking path — routing, `nftables`, `conntrack`, and (when
the client sits behind WireGuard) per-packet WG encryption — before reaching the
NIC. Profiling a live client at ~40–60 Mbit showed CPU dominated not by crypto
or the userspace stack but by this per-packet kernel work (`nft_do_chain`,
`nf_conntrack_*`, `fib_*`, `tun_get_user`, `wg_xmit`), with `write(2)` the top
syscall by count.

GSO/TSO offload on the TUN device hands the kernel **one large super-segment
(up to ~60 KB)** instead of N MSS-sized packets, so routing / `nftables` /
`conntrack` / WG run **once per super-segment** rather than once per MSS.

## What `gso = true` does

- Opens the TUN device with `IFF_VNET_HDR`, so every `read(2)` / `write(2)`
  carries a 10-byte `virtio_net_hdr` prefix.
- **Downlink (write):** `flush` coalesces queued server→client data into one
  TCP super-segment (up to ~60 KB) with a `virtio_net_hdr` describing the MSS
  (`gso_size`) and a **partial (pseudo-header) checksum**; the kernel splits it
  into MSS segments, filling in each segment's sequence number and finalising
  its L4 checksum. This is where the CPU win lands.
- **Retransmit stays per-MSS:** the send scoreboard tracks each MSS segment
  individually, so a loss inside a super-segment is recovered at MSS
  granularity (a lone MSS packet), exactly as without GSO.
- **Read side is unchanged:** we deliberately do *not* request `TUNSETOFFLOAD`,
  which only affects the read direction (it would make the kernel hand us GRO
  super-packets to resegment). Without it the kernel segments to ≤MSS before we
  read, so the uplink path is byte-for-byte as before.

## Enabling

```toml
[tun]
gso = true
```

Linux only; ignored on other targets. Requires a kernel with `IFF_VNET_HDR`
(present since 2.6.27) that forwards GSO super-packets into WireGuard (6.x — the
kernel segments in software before WG if needed, but the per-packet routing /
`nftables` / `conntrack` cost is already paid once per super-segment).

## Validating

The write path is data-plane core, so confirm **data integrity** first, then the
CPU win:

1. Set `gso = true`, restart the client.
2. Download a large file through the tunnel and check its `sha256sum` matches the
   original — bytes must be identical (a wrong offload checksum would corrupt
   silently, though TCP/QUIC checks downstream would usually break the transfer).
3. Confirm normal browsing / streaming works.
4. Compare CPU and `write(2)` rate against `gso = false` at the same throughput:
   `sudo timeout 5 strace -f -c -p $(pidof outline-ws-rust)` — the `write` count
   should drop sharply (one write per super-segment instead of per MSS), and
   `perf top` should show less time in the kernel networking path.

## Rollback

`gso = false` (the default) restores the exact previous per-packet path; no
rebuild is needed, only a restart.
