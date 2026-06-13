# Reverse Tunnel (Topology A)

This document describes the reverse-tunnel feature, which lets the
`outline-ss-rust` server run **behind NAT without a public IP** by dialing
out to a public `outline-ws-rust` client that listens for it.

*Русская версия: [REVERSE-TUNNEL.ru.md](REVERSE-TUNNEL.ru.md)*

## Why

In the normal ("forward") deployment the server is public and the client
dials in. Sometimes that is inverted: the machine with the *clean* egress IP
(the one you want traffic to exit from) sits behind NAT, and the only public
host you control is the one users connect to. Topology A makes that work:

- `outline-ss-rust` (the **server**, behind NAT) dials *out* over QUIC to a
  public `outline-ws-rust`.
- `outline-ws-rust` (the **client**, public VPS) **listens**, accepts the
  carrier, and routes user SOCKS5/TUN traffic out through it.
- User traffic enters on `ws`; it leaves the internet from `ss`'s egress IP.

## How it works

Only the **carrier direction** is inverted. The stream-level data plane is
unchanged from the forward path, because QUIC lets either peer open
bidirectional streams regardless of who dialed the connection:

| Role | Forward deployment | Reverse (topology A) |
|------|--------------------|----------------------|
| `ss` | QUIC server (`accept`) | QUIC **client** (`connect`), still `accept_bi` |
| `ws` | QUIC client (`connect`) | QUIC **server** (`accept`), opens `bi` per session |
| TLS  | `ss` presents server cert | inverted: `ws` presents server cert, `ss` presents client cert (mTLS) |

Each user session is one QUIC bidi stream carrying either raw Shadowsocks
(SS-AEAD / SS-2022) or VLESS, exactly like the forward raw-QUIC transport —
the wire protocol is chosen **per peer** and negotiated by the carrier's
ALPN (`ss`/`ss-mtu` vs `vless`/`vless-mtu`), so one listener can serve a mix
of SS and VLESS peers. UDP rides QUIC datagrams (VLESS muxes per-target
sessions by id). The `ss` server reuses its existing raw-SS / raw-VLESS
accept loops unchanged — they do not care that the carrier was dialed
outbound.

### Authentication: mTLS + pinned certificates

CDN fronting is not applicable to the reverse carrier, so neither side uses
the public webpki trust store. Instead both ends pin the other's certificate
by **SHA-256 fingerprint**, and the listener requires a client certificate
(mutual TLS):

- `ss` presents a **client certificate**; `ws` accepts the carrier only if
  that cert's fingerprint is in its allow-list.
- `ws` presents a **server certificate**; `ss` completes the handshake only
  if that cert's fingerprint matches the pin it was configured with.

A peer's client-cert fingerprint also selects *which* configured peer
connected, and therefore which framing credentials the listener uses for
that peer's streams — Shadowsocks `method` / `password` for an SS peer, or
the `vless_id` UUID for a VLESS peer — and which egress `group` it joins.

## Setup

### 1. Generate the certificate pair

Two self-signed certs are needed: one the `ws` listener presents, one the
`ss` dialer presents. Any tool works; with OpenSSL:

```bash
# ws server certificate (presented by the public listener)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ws-server.key -out ws-server.crt -days 3650 \
  -subj "/CN=reverse" -addext "subjectAltName=DNS:reverse"

# ss client certificate (presented by the dialer behind NAT)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ss-client.key -out ss-client.crt -days 3650 \
  -subj "/CN=reverse-ss" -addext "subjectAltName=DNS:reverse-ss"
```

Compute each cert's SHA-256 fingerprint over its **DER** encoding — this is
the pin string the other side configures (hex, optionally colon-separated,
or base64 of the 32 bytes):

```bash
openssl x509 -in ws-server.crt -outform DER | openssl dgst -sha256
openssl x509 -in ss-client.crt -outform DER | openssl dgst -sha256
```

### 2. Configure the public `ws` listener

```toml
[reverse_listener]
enabled = true
# UDP address the QUIC server endpoint binds.
listen = "0.0.0.0:8443"
# Certificate this listener presents to dialing peers.
server_cert_path = "/etc/outline-ws/ws-server.crt"
server_key_path  = "/etc/outline-ws/ws-server.key"
# Default uplink group reverse peers are pooled under (per-peer `group`
# overrides this). Route traffic here via [[route]].
group = "reverse"
# true (default) offers ss-mtu then ss (enables the oversize-record fallback).
mtu = true
# Upper bound on concurrently-registered peers, applied per group (default 8).
max_peers = 8

# One entry per expected peer. `client_cert_pin` authenticates the carrier
# (mTLS). The peer's protocol is per-peer: an SS peer gives `method` +
# `password` (must match an ss user); a VLESS peer gives `vless_id` (a UUID,
# must match an ss `[vless]` user) — exactly one of the two forms. `group`
# is optional — omit it to join the listener-level `group`, or set it to
# pool distinct peers under distinct egress groups served by distinct routes.
[[reverse_listener.peers]]
client_cert_pin = "aa:bb:cc:..."          # SHA-256 of ss-client.crt (DER)
method   = "2022-blake3-aes-256-gcm"      # SS peer
password = "<base64-psk-or-password>"
# group omitted → joins the listener default ("reverse").

[[reverse_listener.peers]]
client_cert_pin = "11:22:33:..."          # a second peer, VLESS, separate egress
vless_id = "b831381d-6324-4d53-ad4f-8cda48b30811"   # must match an ss [vless] user
group    = "reverse-eu"                    # pooled and routed separately
```

The VLESS peer above dials in with the `vless`/`vless-mtu` ALPN; the SS peer
with `ss`/`ss-mtu`. The single listener advertises both and routes each
carrier to its protocol's accept loop.

Route each reverse group like any other uplink group:

```toml
[[route]]
# Specific destinations egress through the second peer.
prefixes = ["203.0.113.0/24"]
via = "reverse-eu"

[[route]]
# Everything else egresses through the default peer.
default = true
via = "reverse"
```

When no peer is connected for a group, it falls through to that group's
configured uplinks (if any) or fails the session — it never silently drops.

### 3. Configure the `ss` dialer (behind NAT)

```toml
[reverse_tunnel]
enabled = true

[[reverse_tunnel.endpoints]]
# host:port of the public ws listener. host may be a DNS name or literal IP.
addr = "ws.example.com:8443"
# TLS SNI / server name. Defaults to the host part of `addr`.
server_name = "reverse"
# SHA-256 of ws-server.crt (DER) — pins the listener's cert (no webpki).
server_cert_pin = "dd:ee:ff:..."
# Client certificate presented for mTLS (its pin is allow-listed on ws).
client_cert_path = "/etc/outline-ss/ss-client.crt"
client_key_path  = "/etc/outline-ss/ss-client.key"
# Wire protocol carried over this carrier: "ss" (default) or "vless". Must
# match the protocol of the matching peer entry on the ws listener; selects
# the ALPN offered (ss/ss-mtu vs vless/vless-mtu) and the accept loop run.
protocol = "ss"
# true (default) offers the -mtu ALPN sibling first; false offers only the base.
mtu = true
# Reconnect backoff floor / ceiling in seconds for transient failures
# (default 1 / 60).
backoff_min_secs = 1
backoff_max_secs = 60
```

The user that frames traffic (the `ws` peer entry's `method` / `password`,
or `vless_id`) must exist in the `ss` server's `[[users]]` (SS) or `[vless]`
users (VLESS) so the handshake authenticates — mTLS identity and the SS/VLESS
user are independent layers.

Each endpoint runs its own reconnect loop with bounded, jittered backoff. A
malformed pin or unreadable certificate disables only that one endpoint
(logged at startup) without aborting the server.

The loop distinguishes **transient failures** (the `ws` host is down, a
timeout, a network blip) from **authentication failures** (a pin/cert
mismatch — whether `ss` rejects the `ws` server cert or `ws` rejects the
`ss` client cert). Transient failures retry on the exponential
`backoff_min_secs`→`backoff_max_secs` schedule; an authentication failure
will not fix itself on retry, so the loop backs off a long, fixed interval
(5 minutes) and logs a warning to check the pins/certs, rather than
hammering the peer with TLS handshakes. It keeps probing at that interval,
so once the certificate problem is corrected (which on `ss` means a
restart, as the reverse config is not hot-reloaded) the carrier re-forms on
its own.

## Observability

| Metric | Side | Meaning |
|--------|------|---------|
| `outline_ss_reverse_tunnel_active_connections` | ss | Gauge of established carriers. |
| `outline_ss_reverse_tunnel_connects_total{result}` | ss | Dial outcomes (`success` / `failure`). |
| `outline_ws_rust_reverse_peers{group}` | ws | Gauge of currently-connected peers per group. |

Labels stay low-cardinality; peer certificate fingerprints are never logged
or exported.

## Limitations

- **Raw Shadowsocks and VLESS** are carried on the reverse carrier (both
  TCP and UDP). HTTP/3-WebSocket is not carried in reverse mode.
- **No CDN fronting** — the carrier is a direct QUIC connection authenticated
  by pinned certificates, not a CDN-frontable HTTPS request.
- Peers are pooled **per egress group** (a peer's `group`, defaulting to the
  listener-level `group`) with round-robin balancing across the live peers in
  that group; a peer whose carrier drops is evicted on the next selection. One
  listener — a single bound port, server cert and pin allow-list — fans out to
  as many groups as the peers declare.
- QUIC keep-alive (10 s) on both ends keeps the NAT mapping alive from the
  `ss` side — the case the feature exists for.
