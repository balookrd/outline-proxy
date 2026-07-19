# TUN GSO / GRO / USO offload (`[tun] gso`, `[tun] gro`, `[tun] uso`)

*Русская версия: [TUN-GSO.ru.md](TUN-GSO.ru.md)*

## Why

The TUN client terminates TCP in userspace, so every downlink segment it
delivers to the client is written to the TUN device with a separate `write(2)`,
and every uplink segment the client sends arrives as a separate `read(2)`. On a
busy link that is thousands of syscalls per second, and each packet traverses
the full kernel networking path — routing, `nftables`, `conntrack`, and (when
the client sits behind WireGuard) per-packet WG encryption — before reaching the
NIC or our stack. Profiling a live client at ~40–60 Mbit showed CPU dominated
not by crypto or the userspace stack but by this per-packet kernel work
(`nft_do_chain`, `nf_conntrack_*`, `fib_*`, `tun_get_user`, `wg_xmit`), with
`write(2)` the top syscall by count.

Offload batches packets so the kernel and our stack run **once per super-packet**
rather than once per MSS:

- **`gso` (downlink / write, TSO):** we hand the kernel one large super-segment
  (up to ~60 KB) instead of N MSS packets; the kernel splits it per MSS *after*
  routing / `nftables` / `conntrack` / WG have run once.
- **`gro` (uplink / read, GRO):** the kernel coalesces several inbound MSS
  segments of one flow into one >MSS super-packet (up to 64 KB) and hands it to
  us whole, so our read / parse / TCP-stack work runs once instead of per MSS.

## What `gso = true` does

- Opens the TUN device with `IFF_VNET_HDR`, so every `read(2)` / `write(2)`
  carries a 10-byte `virtio_net_hdr` prefix.
- **Downlink (write):** `flush` coalesces queued server→client data into one
  TCP super-segment (up to ~60 KB) with a `virtio_net_hdr` describing the MSS
  (`gso_size`) and a **partial (pseudo-header) checksum**; the kernel splits it
  into MSS segments, filling in each segment's sequence number and finalising
  its L4 checksum. This is where the downlink CPU win lands.
- **Retransmit stays per-MSS:** the send scoreboard tracks each MSS segment
  individually, so a loss inside a super-segment is recovered at MSS
  granularity (a lone MSS packet), exactly as without GSO.
- On its own, `gso` does **not** request `TUNSETOFFLOAD`, so the read path is
  byte-for-byte as before — the uplink is covered by the separate `gro`
  opt-in.

## What `gro = true` does (requires `gso`)

- Requests `TUNSETOFFLOAD` with `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6`, telling
  the kernel it may coalesce inbound **TCP** into GRO super-packets (up to
  64 KB, `gso_type` TCPV4/6) instead of pre-segmenting to ≤MSS.
- **Uplink (read):** the read loop feeds the oversized TCP segment straight
  into the userspace TCP engine, whose receive path already accepts segments far
  larger than one MSS (it sizes from the IP total length, buffers as `Bytes`,
  and trims to the receive window). `TUN_F_CSUM` also enables RX checksum
  offload, so the kernel may leave the L4 checksum un-finalised; the read loop
  recomputes it from the trusted payload.
- **UDP stays per-datagram:** `TUN_F_USO4/6` is deliberately **not** requested,
  so without `NETIF_F_GSO_UDP_L4` the kernel re-segments UDP GRO back into
  datagrams before we read them. (Should a UDP super-packet arrive anyway, the
  read loop re-segments it back into datagrams, so UDP behaviour is unchanged
  either way.)
- **Coalescing only happens on a burst:** GRO merges segments only when the
  source actually bursts (bulk upload, or a forwarding path with
  `generic-receive-offload` on the inbound NIC). ACK-only / interactive uplink
  stays per-packet — that is expected.
- If the kernel rejects `TUNSETOFFLOAD`, the client logs a warning and continues
  without GRO; the write-side TSO still works.

## What `uso = true` does (requires `gso`)

- Requests `TUNSETOFFLOAD` with `TUN_F_CSUM | TUN_F_USO4 | TUN_F_USO6`, letting
  the writer hand the kernel one `GSO_UDP_L4` super-segment (up to 64 datagrams
  / ~60 KB) that it splits into equal `gso_size` datagrams — the UDP analogue of
  `gso`'s TCP TSO, on the **write** path.
- **Downlink (write):** the per-flow reader coalesces consecutive equal-sized
  datagrams of one flow (its 4-tuple is fixed, so all reply to the same
  destination) into one super-segment carrying a partial (pseudo-header)
  checksum the kernel finalises per datagram. A different-sized datagram ends
  the batch and is carried to the next one (zero-loss). This is the win for
  bulk QUIC video, where the downlink is the heavy UDP direction.
- **`TUN_F_USO` also enables RX UDP GRO:** the kernel may hand us coalesced UDP
  super-packets on read, which the read loop re-segments back into datagrams
  (`resegment_udp_gso`), so UDP receive behaviour is unchanged.
- `TUN_F_CSUM` (mandatory for USO) turns on RX checksum offload; the read loop
  recomputes any un-finalised checksum.
- If the kernel rejects USO (< 5.18), the client logs and keeps TCP offload;
  UDP GSO is disabled.

## Enabling

**All three are on by default** — `gso = true`, with `gro` and `uso` following
`gso` unless set explicitly:

```toml
[tun]
gso = true   # downlink TSO (default)
gro = true   # uplink GRO (default: follows gso)
uso = true   # downlink UDP USO (default: follows gso)
```

Linux only; ignored on other targets. `gso` needs a kernel with `IFF_VNET_HDR`
(since 2.6.27) — without it the attach falls back to the plain per-packet path
with a log line. `gro`/`uso` additionally need `TUNSETOFFLOAD` support; `uso`
needs `GSO_UDP_L4` (kernel ≥ 5.18) — a rejected offload is logged and the rest
is kept. `gro` and `uso` can be toggled independently of each other and of
`gso`.

> **Persistent interface caveat.** `TUNSETOFFLOAD` sets feature flags on the
> device that survive a process restart on a *persistent* TUN interface. The
> client re-applies the offload state explicitly on every attach (including
> clearing it to `0` when disabled), so a plain restart normally suffices. If
> you ever see a stuck `tx-udp-segmentation: off [requested on]` in `ethtool -k`
> after a restart, drive a real feature transition with `ethtool -K <tun>
> tx-udp-segmentation off …` (then restart), or recreate the interface
> (`ip link del` / `ip tuntap add`).

## Validating

All three paths are data-plane core, so confirm **data integrity** first, then
the CPU win:

1. Enable the flag(s), restart the client.
2. **Downlink (`gso`):** download a large file through the tunnel and check its
   `sha256sum` matches the original — bytes must be identical.
3. **Uplink (`gro`):** upload a large file through the tunnel and check its
   `sha256sum` on the far end.
4. **UDP (`uso`):** confirm UDP is healthy (DNS resolves, QUIC / YouTube plays)
   and run a bulk UDP transfer; the `outline_ws_tun_packets_total{outcome=
   "uso_supersegment"}` counter rising means downlink datagrams are coalescing.
5. Compare CPU and syscall rate against the disabled state at the same
   throughput: `sudo timeout 5 strace -f -c -p $(pidof outline-ws-rust)` — with
   `gso`, `write` should drop sharply; with `gro` on a bulk uplink, `read`
   should.

Reading offload back with `ethtool -k <tun>`:

- **`gso` (write-side downlink TSO) is invisible in `ethtool`.** It rides the
  per-`read`/`write` `virtio_net_hdr` on the fd (attached with `IFF_VNET_HDR`),
  which is a queue property, not a netdevice feature — no `ethtool` line
  reflects it. Our `TUN loop started` / `TUN offload negotiated` log lines
  (`gso=true`) are the only confirmation.
- **`gro` and `uso` DO show up**, because they are set via `TUNSETOFFLOAD`, which
  flips real netdevice features. With both on you should see, all `on`:
  `tx-checksum-ip-generic` (mandatory `TUN_F_CSUM`), `tx-tcp-segmentation` +
  `tx-tcp6-segmentation` (`gro`'s `TUN_F_TSO4/6`), and `tx-udp-segmentation`
  (`uso`'s `TUN_F_USO4/6`). A healthy `uso` reads `tx-udp-segmentation: on`
  *without* a trailing `[requested on]` — the `[requested on]` form is the stuck
  state described in the persistent-interface caveat above.
- **`generic-segmentation-offload` / `generic-receive-offload` are NOT our
  flags** — those are the kernel's own software GSO/GRO for the device and are
  irrelevant here; ignore their state.

## Rollback

`gso = false` restores the exact previous per-packet path (`gro` and `uso`
follow it down unless set explicitly); no rebuild is needed, only a restart.
`gro = false` / `uso = false` each drop only their own offload while leaving
the downlink TSO in place, so all three roll back independently. Do **not**
disable `uso` alone while keeping `gso`: with `IFF_VNET_HDR` the kernel frames
local UDP-GSO (QUIC/HTTP3 egress) as `GSO_UDP_L4` super-packets that are only
delivered intact when `TUN_F_USO` is on — `gso` without `uso` breaks UDP.
