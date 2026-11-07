# Outbound IPv6 source selection

*Русская версия: [OUTBOUND-IPV6.ru.md](OUTBOUND-IPV6.ru.md)*

How `outline-proxy` chooses the source IPv6 address for traffic it sends to the
internet: the server's upstream connections (`outline-ss-rust`) and the
client's direct-route dials (`outline-ws-rust`, the `via = "direct"` / TUN
bypass path). Operators usually want one of two opposite things:

- Stability: keep long-lived connections (SSH, map tiles, streaming) alive
  while the host rotates IPv6 privacy-extension addresses.
- Rotation: spread outbound traffic across many source addresses so an
  observer cannot correlate all of it to one address.

## How return traffic limits the choice

Picking a source address is the easy half. The hard half is getting the reply
back. Three conditions decide what works:

1. NDP. On a shared SLAAC segment the upstream router sends a Neighbor
   Solicitation for each destination address and forwards the reply only once
   some host answers. The kernel answers only for addresses configured on an
   interface. A random, unconfigured source address therefore gets no reply
   unless something proxies NDP for it.
2. Routing. If the whole prefix is routed to the host (DHCPv6-PD delegation or
   a manual AnyIP route), every address in it gets replies without NDP.
3. Anti-spoofing (RPF / BCP38). The upstream may drop packets whose source is
   not assigned to you. A home router (for example, Keenetic) usually does not;
   an ISP on a shared segment might.

`IPV6_FREEBIND` lets a socket bind a non-local address, but it does not help
with (1)–(3): those are network-layer conditions you must satisfy separately.

## Server modes (`[outbound]` / `--outbound-ipv6-*`)

Set exactly one source mode; the loader rejects a config with more than one
(`... are mutually exclusive; pick one`).

| Mode | Config key | Source pool | Return traffic needs |
|------|-----------|-------------|----------------------|
| Static prefix | `ipv6_prefix = "2a01:…::/64"` | whole CIDR (random per connect) | `IPV6_FREEBIND` + prefix on-link, or an AnyIP route; the whole /64 routed or NDP-answered |
| Interface pool | `ipv6_interface = "enp1s0"` | addresses configured on the interface | nothing extra: the kernel owns the addresses and answers their NDP (works under plain SLAAC) |
| Dynamic prefix | `ipv6_prefix_interface = "enp1s0"` | whole current /64 of the interface, re-derived on refresh | same as static prefix (NDP proxy / ndppd), but the /64 is discovered, not hard-coded |

### `ipv6_prefix`: static prefix

Binds a random address from a fixed CIDR. Use it when you own a routed prefix
that never changes. The prefix must be reachable back to the host: on-link plus
`IPV6_FREEBIND` (set automatically), or an AnyIP route
`ip -6 route add local <prefix> dev lo`, where `<prefix>` is the CIDR from
`ipv6_prefix`.

### `ipv6_interface`: interface address pool

Enumerates the global addresses currently on the interface and binds a random
one. Because they are configured addresses, the kernel answers their NDP and RPF
passes; this is the only mode that works on a plain SLAAC segment without
ndppd. With privacy extensions (`use_tempaddr=2`) the pool follows the rotating
temporary addresses. On Linux the pool is read from `/proc/net/if_inet6`, and
deprecated, tentative and dadfailed addresses are skipped, so a temporary
address about to be removed is never picked (a flow on it would break when it
is removed).

### `ipv6_prefix_interface`: dynamic prefix from interface

Derives the interface's current global /64 and binds a random address across
the whole prefix, like the static prefix, but re-derives the /64 on every
refresh (`ipv6_refresh_secs`, default 30). Use it when the prefix is dynamic,
for example when a provider delegates a prefix that changes on every reconnect
and a router (Keenetic) re-advertises it into the LAN via SLAAC. Like the static
prefix, it needs the whole /64 routed back; see
[NDP proxy (ndppd) for the prefix modes](#ndp-proxy-ndppd-for-the-prefix-modes).

### Sticky source

`ipv6_sticky = true` (default) with `ipv6_sticky_ttl_secs` (default 1800) pins
one source per destination IP for the TTL, so that, for example, a Cloudflare
`cf_clearance` challenge stays valid across a client's successive requests.
Different destinations still get different sources, and a destination gets a
new source after the TTL. Without a prefix or interface source mode the setting
has no effect.

## Client, direct route (`outline-ws-rust`)

The client's uplink traffic is tunnelled to your server and its source is never
rotated. These settings apply only to the direct route (`via = "direct"` / TUN
bypass), where the client talks to the internet itself.

### `prefer_public_ipv6_src`: stable source (default `true`)

Sets `IPV6_PREFER_SRC_PUBLIC` (RFC 5014) on outbound IPv6 sockets so the kernel
picks the stable public/SLAAC address instead of a rotating privacy-extension
temporary address. Without it, direct IPv6 connections break when the temporary
address's `valid_lft` expires and the kernel removes it. Set `false` to use
privacy-extension rotation for the source on purpose, accepting that long flows
break on `valid_lft` expiry. The host's `use_tempaddr` does not change this
choice; only the config key does. Linux only; kernels without the option ignore
it.

### `direct_ipv6_prefix_interface`: rotating /64 (opt-in)

The client counterpart of the server's `ipv6_prefix_interface`: each direct
IPv6 dial binds a random address from the interface's current /64, re-read from
`/proc/net/if_inet6` on every connect, so it follows a dynamic prefix. Return
traffic has the same requirement: the /64 must be routed back to the host via
ndppd. When set, it takes precedence over `prefer_public_ipv6_src` for direct
dials.

## Choosing a mode

```
Do you control a prefix that is ROUTED to the host (DHCPv6-PD, AnyIP)?
├── Yes, and it is static             → server: ipv6_prefix
├── Yes, but it changes (PD/reconnect)→ *_prefix_interface  (+ ndppd)
└── No — plain SLAAC shared segment
        ├── want rotation across the whole /64 → *_prefix_interface + ndppd
        │     (only if the upstream/router does NOT do strict RPF — test first)
        ├── want rotation, NDP/RPF not solvable → server: ipv6_interface
        │     (rotates over real temporary addresses only)
        └── want stability (no rotation)        → client: prefer_public_ipv6_src
```

`*_prefix_interface` is the server's `ipv6_prefix_interface` or the client's
`direct_ipv6_prefix_interface`.

A common topology: ISP → Keenetic (gets a prefix via DHCPv6-PD that changes on
reconnect) → SLAAC /64 into the LAN → host. The host sees a dynamic `proto ra`
/64 on a shared segment, so the whole-/64 modes need ndppd, and the prefix must
be re-derived, which the `*_prefix_interface` modes do.

## NDP proxy (ndppd) for the prefix modes

The prefix modes (`ipv6_prefix`, `ipv6_prefix_interface` and the client's
`direct_ipv6_prefix_interface`) bind random, unconfigured addresses. On a SLAAC
segment the host must answer NDP for the whole /64 so replies return; `ndppd`
does this. Because the /64 is dynamic, the proxied prefix must follow it:
`scripts/ndppd-prefix-sync.sh`, run by `ndppd-prefix-sync.timer` every 30 s,
reads the current RA `/64` of `IFACE` and rewrites `/etc/ndppd.conf` when it
changes.

Run as root on the host, from the repository checkout. The service unit sets
`IFACE=enp1s0`; edit `Environment=IFACE=` in
`/etc/systemd/system/ndppd-prefix-sync.service` for another interface, and
replace `enp1s0` in the `proxy_ndp` line below as well.

```sh
apt install ndppd
install -m 0755 scripts/ndppd-prefix-sync.sh /usr/local/sbin/
install -m 0644 scripts/ndppd-prefix-sync.service scripts/ndppd-prefix-sync.timer /etc/systemd/system/
# ndppd needs forwarding + proxy_ndp (pin these in /etc/sysctl.d/):
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.enp1s0.proxy_ndp=1
systemctl daemon-reload
systemctl enable --now ndppd ndppd-prefix-sync.timer
```

Check: `cat /run/ndppd-prefix.state` prints the /64 the script last wrote,
`/etc/ndppd.conf` has a `rule <prefix>` block under `proxy <IFACE>`, and each
change is logged with the tag `ndppd-prefix-sync`
(`journalctl -t ndppd-prefix-sync`).

## Rotation and long-lived connections

When the prefix lifetime is short, rotation and long-lived connections conflict:

- The interface pool mode rotates over the kernel's temporary addresses. A long
  connection survives only until its source address's `valid_lft` expires and
  the kernel removes it; then it breaks. The code cannot prevent that: the
  lifetime comes from the RA `valid_lft`, which the upstream sets.
- If you control the router and can raise the RA `valid_lft`, set
  `temp_prefered_lft` short (frequent rotation for new connections) and
  `temp_valid_lft` long (old addresses stay, so existing flows survive). The
  ceiling for `temp_valid_lft` is the RA-advertised `valid_lft`.
- If the prefix lifetime is short and you cannot change it, choose per host
  between rotation and long-flow stability with the settings above.
- The `*_prefix_interface` modes derive the prefix from a preferred (never a
  deprecated) address, so a new flow is less likely to land on a prefix about to
  disappear.

## Verifying return traffic

Before relying on any whole-/64 prefix mode, check that the upstream accepts an
unconfigured source (NDP + RPF). Run as root; replace `2a01:…:dead` with an
unused address from your /64 and `enp1s0` with your interface:

```sh
ip -6 addr add 2a01:…:dead/64 dev enp1s0 nodad
ping6 -c3 -I 2a01:…:dead 2606:4700:4700::1111   # replies → NDP/RPF OK
ip -6 addr del 2a01:…:dead/64 dev enp1s0
```

No reply means the segment does not return traffic for arbitrary sources; use
`ipv6_interface` (server) or `prefer_public_ipv6_src` (client) instead.

Commands to inspect the current state:

```sh
ip -6 route show proto ra                 # current dynamic /64 (and its expiry)
ip -6 addr show dev enp1s0                 # temporary vs. mngtmpaddr, lifetimes
sysctl net.ipv6.conf.{all,default}.use_tempaddr   # is rotation enabled?
```

## Config reference

Server (`outline-ss-rust`): the `[outbound]` block or the CLI flags. A flag
(or its environment variable) overrides the config key.

| Key | CLI flag / environment variable | Default | Meaning |
|-----|---------------------------------|---------|---------|
| `ipv6_prefix` | `--outbound-ipv6-prefix` / `OUTLINE_SS_OUTBOUND_IPV6_PREFIX` | unset | static CIDR source pool |
| `ipv6_interface` | `--outbound-ipv6-interface` / `OUTLINE_SS_OUTBOUND_IPV6_INTERFACE` | unset | interface address pool |
| `ipv6_prefix_interface` | `--outbound-ipv6-prefix-interface` / `OUTLINE_SS_OUTBOUND_IPV6_PREFIX_INTERFACE` | unset | dynamic /64 derived from the interface |
| `ipv6_refresh_secs` | `--outbound-ipv6-refresh-secs` / `OUTLINE_SS_OUTBOUND_IPV6_REFRESH_SECS` | 30 | re-enumerate / re-derive interval, seconds |
| `ipv6_sticky` | `--outbound-ipv6-sticky` / `OUTLINE_SS_OUTBOUND_IPV6_STICKY` | `true` | pin the source per destination IP |
| `ipv6_sticky_ttl_secs` | `--outbound-ipv6-sticky-ttl-secs` / `OUTLINE_SS_OUTBOUND_IPV6_STICKY_TTL_SECS` | 1800 | sticky pin TTL, seconds |

Client (`outline-ws-rust`, top-level config keys):

| Key | Default | Meaning |
|-----|---------|---------|
| `prefer_public_ipv6_src` | `true` | stable public source for direct IPv6; `false` → privacy-extension rotation |
| `direct_ipv6_prefix_interface` | unset | rotating /64 source for direct IPv6 (needs ndppd) |
| `direct_fwmark` | unset | `SO_MARK` on direct-route sockets so their traffic is not routed back into the TUN device; Linux only |
