# Outbound IPv6 Source Selection

*Русская версия: [OUTBOUND-IPV6.ru.md](OUTBOUND-IPV6.ru.md)*

How `outline-proxy` chooses the **source** IPv6 address for traffic it sends
out to the real internet — both the server's upstream connections
(`outline-ss-rust`) and the client's direct-route dials (`outline-ws-rust`,
the `via = "direct"` / TUN bypass path). The goal is usually one of two
opposite things, and they trade off against each other:

- **Stability** — keep long-lived connections (SSH, map tiles, streaming)
  alive even while the host rotates IPv6 privacy-extension addresses.
- **Rotation** — spread outbound traffic across many source addresses so an
  observer cannot trivially correlate all of it to one address.

## How return traffic constrains everything

Picking a source address is the easy half. The hard half is making the
**reply** come back. Three facts decide what is possible:

1. **NDP.** On a shared SLAAC segment the upstream router sends a Neighbor
   Solicitation for each destination address and only forwards the reply once
   some host answers. The kernel answers only for addresses actually
   configured on an interface. So a *random* source address (not configured)
   gets no reply unless something proxies NDP for it.
2. **Routing.** If the whole prefix is *routed* to the host (DHCPv6-PD
   delegation, or a manual AnyIP route), every address in it returns without
   NDP games.
3. **Anti-spoofing (RPF / BCP38).** The upstream may drop packets whose source
   is "not yours". A home router (e.g. Keenetic) usually does not; an ISP on a
   shared segment might.

`IPV6_FREEBIND` lets a socket *bind* a non-local address, but it does nothing
for (1)–(3) — those are network-layer facts you must satisfy separately.

## Server modes (`[outbound]` / `--outbound-ipv6-*`)

Exactly one source mode may be set; they are mutually exclusive.

| Mode | Config key | Source pool | Return traffic needs |
|------|-----------|-------------|----------------------|
| Static prefix | `ipv6_prefix = "2a01:…::/64"` | whole CIDR (random per connect) | `IPV6_FREEBIND` + prefix on-link **or** AnyIP route; whole /64 routed/NDP-answered |
| Interface pool | `ipv6_interface = "enp1s0"` | addresses actually on the interface | nothing extra — kernel owns & NDP-answers them (works under plain SLAAC) |
| Dynamic prefix | `ipv6_prefix_interface = "enp1s0"` | whole current /64 of the interface, re-derived on refresh | same as static prefix (NDP proxy / ndppd), but the /64 is discovered, not hard-coded |

### `outbound_ipv6_prefix` — static prefix
Binds a random address from a fixed CIDR. Use when you own a routed prefix that
never changes. Needs the prefix reachable back to the host (on-link +
`IPV6_FREEBIND`, set automatically, or an AnyIP route
`ip -6 route add local <prefix> dev lo`).

### `outbound_ipv6_interface` — interface address pool
Enumerates the global addresses currently on the interface and binds a random
one. Because they are real, configured addresses, the kernel answers their NDP
and RPF passes — this is the **only mode that works on a plain SLAAC segment
without ndppd**. With privacy extensions (`use_tempaddr=2`) the pool tracks the
rotating temporary addresses. On Linux the pool is read from
`/proc/net/if_inet6` and **deprecated / tentative / dadfailed addresses are
skipped**, so a soon-to-be-removed temporary is never pinned (which would tear
a flow down on rotation).

### `outbound_ipv6_prefix_interface` — dynamic prefix from interface
The middle ground: derives the interface's current global **/64** and binds a
random address across the *whole* prefix (like the static prefix), but
**re-derives the /64 on every refresh** (`outbound_ipv6_refresh_secs`). Use
when the prefix is dynamic — e.g. a provider delegates a prefix that changes on
every reconnect and a router (Keenetic) re-advertises it into the LAN via
SLAAC. Like the static prefix it needs the whole /64 routed back (see the
**NDP proxy (ndppd)** section below).

### Stickiness
`ipv6_sticky = true` (with `ipv6_sticky_ttl_secs`, default 1800) pins one source
per destination IP for the TTL, so e.g. a Cloudflare `cf_clearance` challenge
stays valid across a client's successive requests. Rotation is preserved
*between* destinations and across the TTL window. Harmless no-op without a
prefix/interface source.

## Client, direct route (`outline-ws-rust`)

The client's upstream (uplink) traffic is tunnelled to your server and is never
source-rotated. These settings apply only to the **direct route** (`via =
"direct"` / TUN bypass), where the client talks to the internet itself.

### `prefer_public_ipv6_src` — stable source *(default `true`)*
Requests `IPV6_PREFER_SRC_PUBLIC` (RFC 5014) on outbound IPv6 sockets so the
kernel picks the **stable public/SLAAC address** instead of a rotating
privacy-extension temporary. This stops direct IPv6 connections from breaking
when the temporary address's `valid_lft` expires and the kernel removes it.
**Auto-disables** when the host is deliberately rotating
(`net.ipv6.conf.{all,default}.use_tempaddr ≥ 1`), so it never fights an operator
who *wants* rotation. Linux only, best-effort.

### `direct_ipv6_prefix_interface` — rotating /64 *(opt-in)*
The client mirror of the server's `outbound_ipv6_prefix_interface`: each direct
IPv6 dial binds a random address from the interface's current /64 (re-read per
connect from `/proc/net/if_inet6`, so it follows a dynamic prefix). Same
return-traffic requirement — the /64 must be routed back to the host via ndppd.
When set it takes precedence over `prefer_public_ipv6_src` for direct dials.

## Choosing a mode

```
Do you control a prefix that is ROUTED to the host (DHCPv6-PD, AnyIP)?
├── Yes, and it is static            → outbound_ipv6_prefix
├── Yes, but it changes (PD/reconnect)→ *_prefix_interface  (+ ndppd)
└── No — plain SLAAC shared segment
        ├── want rotation across the whole /64 → *_prefix_interface + ndppd
        │     (only if the upstream/router does NOT do strict RPF — test first)
        ├── want rotation, NDP/RPF not solvable → outbound_ipv6_interface
        │     (rotates over real temporary addresses only)
        └── want stability (no rotation)        → client: prefer_public_ipv6_src
```

A common real topology: ISP → Keenetic (gets a prefix via DHCPv6-PD that
changes on reconnect) → SLAAC /64 into the LAN → host. The host sees a dynamic
`proto ra` /64 on a shared segment, so the whole-/64 modes need ndppd, and the
prefix must be re-derived (the `*_prefix_interface` modes do exactly that).

## NDP proxy (ndppd) for the prefix modes

The prefix modes (`outbound_ipv6_prefix`, `*_prefix_interface`, and the client's
`direct_ipv6_prefix_interface`) bind random, **non-configured** addresses. On a
SLAAC segment the host must answer NDP for the whole /64 so replies return.
`ndppd` does this. Because the /64 is dynamic, the proxied prefix must be kept
in sync — `scripts/ndppd-prefix-sync.{sh,service,timer}` re-derives the current
RA `/64` and rewrites `ndppd.conf` on change:

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

## Rotation vs. long-lived connections

This is a genuine, unavoidable trade-off when the prefix lifetime is short:

- The **interface pool** mode rotates over the kernel's temporary addresses. A
  long connection survives only until its source address's `valid_lft` expires
  and the kernel removes it — then it breaks. Code cannot prevent that; it is
  governed by the RA `valid_lft`, which the upstream sets.
- If you can raise the RA `valid_lft` (your own router), set
  `temp_prefered_lft` short (frequent rotation for new connections) and
  `temp_valid_lft` long (old addresses linger so existing flows survive). The
  ceiling for `temp_valid_lft` is the RA-advertised `valid_lft`.
- If the prefix lifetime is short and not controllable, rotation and long-flow
  stability are physically in tension — pick per host with the settings above.
- The `*_prefix_interface` modes always pick a **preferred** (never deprecated)
  address as the prefix, which minimizes how often a freshly-opened flow lands
  on an address about to disappear.

## Verifying

Before relying on any whole-/64 prefix mode, confirm the upstream accepts a
non-configured source (NDP + RPF):

```sh
ip -6 addr add 2a01:…:dead/64 dev enp1s0 nodad
ping6 -c3 -I 2a01:…:dead 2606:4700:4700::1111   # replies → NDP/RPF OK
ip -6 addr del 2a01:…:dead/64 dev enp1s0
```
No reply → the segment won't return traffic for arbitrary sources; use
`outbound_ipv6_interface` (server) or `prefer_public_ipv6_src` (client) instead.

Useful state:
```sh
ip -6 route show proto ra                 # current dynamic /64 (and its expiry)
ip -6 addr show dev enp1s0                 # temporary vs. mngtmpaddr, lifetimes
sysctl net.ipv6.conf.{all,default}.use_tempaddr   # is rotation enabled?
```

## Config reference

Server (`outline-ss-rust`, `[outbound]` block or `--outbound-ipv6-*` flags):

| Key | Default | Meaning |
|-----|---------|---------|
| `ipv6_prefix` | unset | static CIDR source pool |
| `ipv6_interface` | unset | interface address pool |
| `ipv6_prefix_interface` | unset | dynamic /64 derived from interface |
| `ipv6_refresh_secs` | 30 | re-enumerate / re-derive interval |
| `ipv6_sticky` | true | pin source per destination |
| `ipv6_sticky_ttl_secs` | 1800 | sticky TTL |

Client (`outline-ws-rust`, top-level config):

| Key | Default | Meaning |
|-----|---------|---------|
| `prefer_public_ipv6_src` | `true` | stable public source for direct IPv6 (auto-off under rotation) |
| `direct_ipv6_prefix_interface` | unset | rotating /64 source for direct IPv6 (needs ndppd) |
| `direct_fwmark` | unset | SO_MARK for direct sockets (anti-loopback) |
